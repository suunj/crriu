/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "FdModel.h"

#include <sys/socket.h>

#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <limits>
#include <set>
#include <sys/eventfd.h>
#include <sys/epoll.h>

#include "AutoRemoteSyscalls.h"
#include "Event.h"
#include "Task.h"
#include "TraceFrame.h"
#include "kernel_abi.h"
#include "log.h"

using namespace std;

namespace rr {

string FdModel::resolve(Task* t, int dirfd, uintptr_t path_ptr) {
  auto& table = task_tables.at(t->rec_tid)->fds;
  string p = t->read_c_str(remote_ptr<char>(path_ptr));
  if (!p.empty() && p[0] == '/')
    return p;
  if (dirfd == AT_FDCWD)
    return cwd + "/" + p;
  auto it = table.find(dirfd);
  if (it != table.end())
    return it->second->path + "/" + p;
  LOG(warn) << "FdModel: openat relative to unknown dirfd " << dirfd;
  return p;
}

void FdModel::observe(const TraceFrame& frame, Task* t) {
  auto it = task_tables.find(t->rec_tid);
  if (it == task_tables.end()) {
    return;
  }

  if (frame.time() == last_time) {
    return;
  }
  last_time = frame.time();

  auto& table = it->second->fds;

  const Event& ev = frame.event();
  if (!ev.is_syscall_event())
    return;
  const SyscallEvent& sc = ev.Syscall();
  if (sc.state != EXITING_SYSCALL)
    return;

  SupportedArch arch = sc.arch();

  const Registers& r = frame.regs();

  int no = sc.number;
  long ret = r.syscall_result_signed();
  long a0 = r.arg1_signed(), a1 = r.arg2_signed(), a2 = r.arg3_signed();

  if (no == syscall_number_for_openat(arch)) {
    if (ret < 0)
      return;
    auto f = make_shared<OpenFile>();
    f->path = resolve(t, (int)a0, (uintptr_t)a1);
    struct stat st;
    if (stat(f->path.c_str(), &st) == 0 && !S_ISREG(st.st_mode))
        f->seekable = false;
    f->flags = (int)a2;
    f->offset = 0;
    table[(int)ret] = f;
  } else if (no == syscall_number_for_open(arch)) {
    if (ret < 0)
      return;
    auto f = make_shared<OpenFile>();

    f->path = resolve(t, AT_FDCWD, (uintptr_t)a0);
    f->flags = (int)a1;
    f->offset = 0;

    table[(int)ret] = f;
  } else if (no == syscall_number_for_close(arch)) {
    if (ret == 0 && table.count((int)a0)) {
      auto file = table[(int)a0];

      table.erase((int)a0);

      bool still_open = false;

      for (const auto& kv : table) {
        if (kv.second == file) {
          still_open = true;
          break;
        }
      }

      if (!still_open) {
        std::set<OpenFile*> visited;

        for (auto& kv : table) {
          OpenFile* ep = kv.second.get();

          if (!visited.insert(ep).second)
            continue;

          if (ep->type != OpenFile::EPOLL)
            continue;

          for (auto it = ep->epoll_members.begin(); it != ep->epoll_members.end();) {
            if (it->first.file == file)
              it = ep->epoll_members.erase(it);
            else
              ++it;
          }
        }
      }
    }
  } else if (no == syscall_number_for_dup(arch) ||
             (no == syscall_number_for_fcntl(arch) &&
              (a1 == F_DUPFD || a1 == F_DUPFD_CLOEXEC))) {
    if (ret >= 0) {
      int oldfd = (int)a0;
      auto it = table.find(oldfd);
      if (it != table.end())
        table[(int)ret] = it->second;
      else if (oldfd <= 2)
        table[(int)ret] = stdio_alias(oldfd);   // QEMU: fcntl(1, F_DUPFD_CLOEXEC) for the stdio chardev
      else
        table.erase((int)ret);
    }
  } else if (no == syscall_number_for_dup2(arch) ||
    no == syscall_number_for_dup3(arch)) {
    if (ret >= 0) {
      int oldfd = (int)a0;
      int newfd = (int)a1;
      auto it = table.find(oldfd);
      if (it != table.end()) {
        table[newfd] = it->second;
      } else if (oldfd <= 2) {
        table[newfd] = stdio_alias(oldfd);
      } else {
        table.erase(newfd);
      }
    }
  } else if (no == syscall_number_for_lseek(arch)) {
      if (ret >= 0 && table.count((int)a0))
        table[(int)a0]->offset = ret;
  } else if (no == syscall_number_for_read(arch)) {
    if (ret > 0 && table.count((int)a0)) {
      auto& f = table[(int)a0];
      if (f->type == OpenFile::EVENTFD)
        f->counter = (f->flags & EFD_SEMAPHORE) ? f->counter - 1 : 0;
      else if (f->offset >= 0)
        f->offset += ret;
    }
  } else if (no == syscall_number_for_write(arch)) {
    if (ret > 0 && table.count((int)a0)) {
      auto& f = table[(int)a0];
      if (f->type == OpenFile::EVENTFD) {
        f->counter += t->read_mem(remote_ptr<uint64_t>(a1));
      } else if (f->flags & O_APPEND) {
        f->offset = -1;
      } else if (f->offset >= 0) {
        f->offset += ret;
      }
    }
  } else if (no == syscall_number_for_chdir(arch)) {
    if (ret == 0) cwd = resolve(t, AT_FDCWD, (uintptr_t)a0);
  } else if (no == syscall_number_for_eventfd2(arch)) {
    if (ret >= 0) {
      auto f = make_shared<OpenFile>();
      f->type = OpenFile::EVENTFD; f->flags = (int)a1; f->counter = (unsigned)a0;
      table[(int)ret] = f;
    }
  } else if (no == syscall_number_for_signalfd4(arch)) {
    if (ret >= 0 && (int)a0 == -1) {       // a0 != -1 modifies an existing fd
      auto f = make_shared<OpenFile>();
      f->type = OpenFile::SIGNALFD;
      f->sigmask = t->read_mem(remote_ptr<uint64_t>(a1));
      f->flags = (int)r.arg4_signed();
      table[(int)ret] = f;
    }
  } else if (no == syscall_number_for_epoll_create1(arch)) {
    if (ret >= 0) {
      auto f = make_shared<OpenFile>();
      f->type = OpenFile::EPOLL; f->flags = (int)a0;
      table[(int)ret] = f;
    }
  } else if (no == syscall_number_for_epoll_ctl(arch)) {
    if (ret == 0 && table.count((int)a0)) {
      auto& ep = table[(int)a0];
      int fd = (int)a2;
      switch ((int)a1) {
        case EPOLL_CTL_ADD: {
          if (!table.count(fd))
            break;

          uint32_t events =
            t->read_mem(remote_ptr<uint32_t>(r.arg4()));

          uint64_t data =
            t->read_mem(remote_ptr<uint64_t>(r.arg4() + 4));


          ep->epoll_members[{fd, table[fd]}] = {events, data};

          break;
        }

        case EPOLL_CTL_MOD: {
          if (!table.count(fd))
            break;

          uint32_t events =
            t->read_mem(remote_ptr<uint32_t>(r.arg4()));

          uint64_t data =
            t->read_mem(remote_ptr<uint64_t>(r.arg4() + 4));

          auto it = ep->epoll_members.find({fd, table[fd]});
          if (it == ep->epoll_members.end()) {
            LOG(error) << "MOD on unknown epoll membership";
            break;
          }

          it->second.events = events;
          it->second.data = data;
          break;
        }
        case EPOLL_CTL_DEL: {
          auto it = table.find(fd);
          if (it == table.end())
            break;

          ep->epoll_members.erase({fd, it->second});
          break;
        }
      }
    }
  }
  if (is_socket_syscall(no, arch) && ret >= 0 &&
      a0 == AF_UNIX && (a1 & 0xff) == SOCK_DGRAM) {
    auto f = make_shared<OpenFile>();
    f->type = OpenFile::UNIX_DGRAM;
    f->flags = (int)a1;            // SOCK_DGRAM | SOCK_CLOEXEC/NONBLOCK
    table[(int)ret] = f;
    return;
  }
  if (is_connect_syscall(no, arch) && ret == 0) {
    auto it2 = table.find((int)a0);
    if (it2 != table.end() && it2->second->type == OpenFile::UNIX_DGRAM) {
      bool ok = true;
      it2->second->addr = t->read_mem(remote_ptr<uint8_t>((uintptr_t)a1), (size_t)a2, &ok);
      if (!ok) it2->second->addr.clear();
    }
    return;
  }

  if (is_memfd_create_syscall(no, arch) && ret >= 0) {
    auto f = make_shared<OpenFile>();

    f->type = OpenFile::MEMFD;
    f->path = t->read_c_str(remote_ptr<char>((uintptr_t)a0));
    f->flags = (int)a1;
    f->offset = -1;

    table[(int)ret] = f;
    return;
  }
  if (is_mmap_syscall(no, arch) && ret >= 0) {
    // mmap(addr, len, prot, flags, fd, off): remember where a memfd lands so
    // materialize can reopen the same object through /proc/self/map_files.
    int fd = (int)r.arg5_signed();
    auto it2 = table.find(fd);
    if (fd >= 0 && it2 != table.end() && it2->second->type == OpenFile::MEMFD &&
        it2->second->map_start == 0) {
      it2->second->map_start = (uint64_t)ret;
      it2->second->map_len = ((uint64_t)a1 + 4095) & ~4095ULL;
    }
    return;
  }

  if (is_rrcall_init_buffers_syscall(no, arch)) {
    for (auto it2 = table.begin(); it2 != table.end();) {
      if (it2->second->type == OpenFile::UNSUPPORTED &&
        it2->second->origin == "perf_event_open") {
        it2 = table.erase(it2);
      } else {
        ++it2;
      }
    }
    return;
  }

  if ((is_socket_syscall(no, arch) || is_socketpair_syscall(no, arch) ||
    is_pipe_syscall(no, arch) || is_pipe2_syscall(no, arch) ||
    is_accept_syscall(no, arch) || is_accept4_syscall(no, arch) ||
    is_timerfd_create_syscall(no, arch) || is_memfd_create_syscall(no, arch) ||
    is_inotify_init1_syscall(no, arch) || is_userfaultfd_syscall(no, arch) ||
    is_perf_event_open_syscall(no, arch) || is_io_uring_setup_syscall(no, arch)) &&
    frame.regs().syscall_result_signed() >= 0) {

    auto f = std::make_shared<OpenFile>();
    f->type = OpenFile::UNSUPPORTED;
    f->origin = syscall_name(no, arch);
    table[frame.regs().syscall_result()] = f;
  }
  // TODO: fcntl(F_DUPFD*), pread/pwrite (no offset change), readv/writev,
  //       openat2, pipe/socket (kind != regular file), fchdir.
}

bool FdModel::materialize(Task* t) {
  std::map<int, OpenFilePtr> table;

  for (const auto& kv : task_tables.at(t->rec_tid)->fds) {
    if (kv.second->type != OpenFile::UNSUPPORTED) table[kv.first] = kv.second;
  }
  if (table.empty())
    return true;

  // Validate offsets before modifying the tracee's FD table.
  for (const auto& entry : table) {
    int fd = entry.first;
    const auto& file = entry.second;

    if (file->type == OpenFile::REGULAR && file->offset < 0 &&
        !(file->flags & O_APPEND)) {
      LOG(error) << "Cannot restore fd " << fd << ": file offset is unknown";
      return false;
    }
  }

  SupportedArch arch = t->arch();
  AutoRemoteSyscalls remote(t);

  const int close_nr = syscall_number_for_close(arch);
  const int dup2_nr = syscall_number_for_dup2(arch);
  const int openat_nr = syscall_number_for_openat(arch);

  for (int fd = 0; fd < 3; fd++) {
      if (stdio_target[fd]) {
          remote.infallible_send_fd_dup(*stdio_target[fd], fd, 0);
      }
  }

  // Reserve a temporary FD range above every target FD.
  int max_fd = table.rbegin()->first;
  if (max_fd == std::numeric_limits<int>::max())
    return false;

  int min_temp_fd = std::max(max_fd + 1, 1024);

  // Each OpenFile represents one open file description.
  std::map<OpenFile*, int> temporary;
  std::set<int> temp_fds;

  bool ok = true;

  auto close_temp_fds = [&]() {
    for (int fd : temp_fds)
    remote.syscall(close_nr, fd);
  };

  // Phase 1: Open each distinct file description.
  for (const auto& kv : table) {
    OpenFile* f = kv.second.get();

    if (temporary.count(f))
      continue;

    long r = -1;

    auto existing = materialized_files.find(f);

    if (existing != materialized_files.end()) {
      r = remote.infallible_send_fd_if_alive(existing->second);
    } else {
      if (f->type == OpenFile::EVENTFD) {
        r = remote.syscall(
          syscall_number_for_eventfd2(arch),
          (unsigned)f->counter,
          f->flags);
      } else if (f->type == OpenFile::SIGNALFD) {
        AutoRestoreMem mask(remote, &f->sigmask, sizeof(f->sigmask));
        r = remote.syscall(
          syscall_number_for_signalfd4(arch),
          -1, mask.get().as_int(),
          sizeof(f->sigmask), f->flags);
      } else if (f->type == OpenFile::EPOLL) {
        r = remote.syscall(
          syscall_number_for_epoll_create1(arch),
          f->flags);
      } else if (f->type == OpenFile::UNIX_DGRAM) {
        r = remote.syscall(syscall_number_for_socket(arch), AF_UNIX, f->flags, 0);
        if (r >= 0 && !f->addr.empty()) {
          AutoRestoreMem sa(remote, f->addr.data(), f->addr.size());
          long c = remote.syscall(syscall_number_for_connect(arch),
                                  (int)r, sa.get().as_int(), f->addr.size());
          if (c < 0) {
            LOG(error) << "connect for fd " << kv.first << " failed: " << errno_name(-c);
            return false;
          }
        }
      } else if (f->type == OpenFile::MEMFD) {
        if (f->map_start) {
          char p[80];
          snprintf(p, sizeof p, "/proc/self/map_files/%llx-%llx",
                   (unsigned long long)f->map_start,
                   (unsigned long long)(f->map_start + f->map_len));
          AutoRestoreMem path_mem(remote, p);
          r = remote.syscall(openat_nr, AT_FDCWD, path_mem.get().as_int(), O_RDWR, 0);
        } else {
          AutoRestoreMem name_mem(remote, f->path.c_str());
          r = remote.syscall(syscall_number_for_memfd_create(arch),
                             name_mem.get().as_int(), f->flags);
        }
      } else if (f->type == OpenFile::STDIO) {
          r = f->stdio_fd;
      } else {
          AutoRestoreMem path_mem(remote, f->path.c_str());
          r = remote.syscall(
                  openat_nr,
                  AT_FDCWD,
                  path_mem.get().as_int(),
                  f->flags & ~(O_CREAT | O_TRUNC | O_EXCL),
                  0);
      }

      if (r >= 0) {
        ScopedFd shared = remote.retrieve_fd((int)r);

        if (!shared.is_open()) {
          LOG(error) << "Failed to retrieve fd " << r;
          return false;
        }

        materialized_files.emplace(f, std::move(shared));
      }
    }

    // Move the new FD outside the target range.
    // F_DUPFD is a command to fcntl, not a separate syscall.
    long tmp = remote.syscall(
      syscall_number_for_fcntl(arch),
      r, F_DUPFD_CLOEXEC, min_temp_fd);

    if (tmp < 0) {
      LOG(error) << "F_DUPFD_CLOEXEC -> " << tmp;
      remote.syscall(close_nr, r);
      ok = false;
      break;
    }

    if (f->type != OpenFile::STDIO && remote.syscall(close_nr, r) < 0) {
      LOG(error) << "close(" << r << ") failed";
      ok = false;
      break;
    }

    temporary[f] = (int)tmp;
    temp_fds.insert((int)tmp);

    if (f->type != OpenFile::REGULAR || !f->seekable) {
      // Only regular files have an offset to restore.
    } else if (f->offset > 0) {
      long pos = remote.syscall(syscall_number_for_lseek(arch), tmp, f->offset, SEEK_SET);

      if (pos < 0) {
        LOG(error) << "lseek(" << f->path << ") failed: " << pos;
        ok = false;
        break;
      }
      if (pos != f->offset) {
        // noop_llseek (char devices such as /dev/urandom) accepts the seek
        // but leaves f_pos alone; the offset is meaningless there.
        LOG(warn) << "lseek(" << f->path << ") returned " << pos
                  << " for offset " << f->offset << "; unseekable, continuing";
      }
    } else if (f->flags & O_APPEND) {
      long pos = remote.syscall(
        syscall_number_for_lseek(arch), tmp, 0, SEEK_END);

      if (pos < 0) {
        LOG(error) << "lseek(SEEK_END) failed: " << pos;
        ok = false;
        break;
      }
    } else {
      LOG(error) << "Cannot restore file offset: unknown offset";
      ok = false;
      break;
    }
  }

  if (!ok) {
    close_temp_fds();
    return false;
  }

  // Phase 2: Install the target FD numbers.
  for (const auto& kv : table) {
    int target = kv.first;
    int source = temporary.at(kv.second.get());

    long r = remote.syscall(dup2_nr, source, target);

    if (r != target) {
      LOG(error) << "dup2(" << source << ","
        << target << ") -> " << r;
      ok = false;
      break;
    }
  }

  // Phase 2.5: epoll memberships, now that every target fd exists.
  std::set<OpenFile*> restored_epolls;

  for (const auto& kv : table) {
    OpenFile* ep = kv.second.get();

    if (ep->type != OpenFile::EPOLL)
      continue;

    if (!restored_epolls.insert(ep).second)
      continue;

    const int epfd = kv.first;

    for (const auto& m : ep->epoll_members) {
      const EpollKey& key = m.first;
      const EpollMember& member = m.second;

      // Find a live fd referring to the registered OFD.
      int source_fd = -1;

      for (const auto& candidate : table) {
        if (candidate.second == key.file) {
          source_fd = candidate.first;
          break;
        }
      }

      if (source_fd < 0) {
        LOG(error) << "Cannot restore epoll membership: "
          << "no live fd for registered OFD";
        ok = false;
        continue;
      }

      // Check whether the original registered fd already refers
      // to the correct OFD.
      auto current = table.find(key.fd);
      bool needs_remap =
        current == table.end() || current->second != key.file;

      int saved_fd = -1;

      if (needs_remap) {
        // Preserve the current occupant of key.fd, if any.
        if (current != table.end()) {
          saved_fd = remote.syscall(
            syscall_number_for_dup(arch),
            key.fd);

          if (saved_fd < 0) {
            LOG(error) << "dup(" << key.fd
              << ") -> " << saved_fd;
            ok = false;
            continue;
          }
        }

        long r = remote.syscall(
          syscall_number_for_dup2(arch),
          source_fd,
          key.fd);

        if (r < 0) {
          LOG(error) << "dup2(" << source_fd
            << ", " << key.fd << ") -> " << r;
          ok = false;

          if (saved_fd >= 0) {
            remote.syscall(
              syscall_number_for_close(arch),
              saved_fd);
          }
          continue;
        }
      }

      struct {
        uint32_t events;
        uint64_t data;
      } __attribute__((packed)) ev = {
        member.events,
        member.data
      };

      AutoRestoreMem evmem(remote, &ev, sizeof(ev));

      long r = remote.syscall(
        syscall_number_for_epoll_ctl(arch),
        epfd,
        EPOLL_CTL_ADD,
        key.fd,
        evmem.get().as_int());

      if (r != 0) {
        LOG(error) << "epoll_ctl(" << epfd
          << ", ADD, " << key.fd
          << ") -> " << r;
        ok = false;
      }

      // Restore the original fd table.
      if (needs_remap) {
        if (saved_fd >= 0) {
          long restore = remote.syscall(
            syscall_number_for_dup2(arch),
            saved_fd,
            key.fd);

          if (restore < 0) {
            LOG(error) << "Failed to restore fd "
              << key.fd << ": " << restore;
            ok = false;
          }

          remote.syscall(
            syscall_number_for_close(arch),
            saved_fd);
        } else {
          remote.syscall(
            syscall_number_for_close(arch),
            key.fd);
        }
      }
    }
  }
  // Phase 3: Release temporary descriptors.
  close_temp_fds();

  return ok;
}

bool FdModel::apply_cwd(Task* t) {
  SupportedArch arch = t->arch();
  AutoRemoteSyscalls remote(t);
  AutoRestoreMem path_mem(remote, cwd.c_str());

  long ret = remote.syscall(
      syscall_number_for_chdir(arch),
      path_mem.get().as_int());

  if (ret < 0) {
    LOG(error) << "chdir(" << cwd << ") -> " << ret;
    return false;
  }

  return true;
}

void FdModel::init_task(Task* t) {
  task_tables[t->rec_tid] = std::make_shared<ModelFdTable>();
}

void FdModel::fork_task(Task* parent, Task* child, int flags) {
  auto it = task_tables.find(parent->rec_tid);

  if (it == task_tables.end()) {
    FATAL() << "FdModel: no fd table for parent " << parent->rec_tid;
  }

  ModelFdTablePtr child_table =
      (flags & CLONE_SHARE_FILES)
          ? it->second
          : std::make_shared<ModelFdTable>(*it->second);

  task_tables[child->rec_tid] = child_table;

  LOG(debug) << "fork parent=" << parent->rec_tid << " child=" << child->rec_tid
             << " shared=" << !!(flags & CLONE_SHARE_FILES)
             << " fds=" << child_table->fds.size();
}

const std::map<int, FdModel::OpenFilePtr>&
FdModel::fds(Task* t) const {
  return task_tables.at(t->rec_tid)->fds;
}

const void* FdModel::table_id(Task* t) const {
  return task_tables.at(t->rec_tid).get();
}

} // namespace rr
