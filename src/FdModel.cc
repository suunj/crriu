/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "FdModel.h"

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
  } else if (no == syscall_number_for_dup(arch)) {
    if (ret >= 0 && table.count((int)a0))
      table[(int)ret] = table[(int)a0];
  } else if (no == syscall_number_for_dup2(arch) ||
    no == syscall_number_for_dup3(arch)) {
    if (ret >= 0) {
      int oldfd = (int)a0;
      int newfd = (int)a1;

      auto it = table.find(oldfd);

      if (it != table.end()) {
        table[newfd] = it->second;
      } else {
        // The source FD exists in the tracee but is not modeled.
        // Its duplicate must not retain a stale mapping.
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
  // TODO: fcntl(F_DUPFD*), pread/pwrite (no offset change), readv/writev,
  //       openat2, pipe/socket (kind != regular file), fchdir.
}

bool FdModel::materialize(Task* t) {
  auto& table = task_tables.at(t->rec_tid)->fds;
  if (table.empty())
    return true;

  // Validate offsets before modifying the tracee's FD table.
  for (const auto& entry : table) {
    int fd = entry.first;
    const auto& file = entry.second;

    if (file->offset < 0 && !(file->flags & O_APPEND)) {
      LOG(error) << "Cannot restore fd " << fd << ": file offset is unknown";
      return false;
    }
  }

  SupportedArch arch = t->arch();
  AutoRemoteSyscalls remote(t);

  const int close_nr = syscall_number_for_close(arch);
  const int dup2_nr = syscall_number_for_dup2(arch);
  const int openat_nr = syscall_number_for_openat(arch);

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

    long r;
    if (f->type == OpenFile::EVENTFD) {
      r = remote.syscall(syscall_number_for_eventfd2(arch),
                         (unsigned)f->counter, f->flags);
    } else if (f->type == OpenFile::SIGNALFD) {
      AutoRestoreMem mask(remote, &f->sigmask, sizeof(f->sigmask));
      r = remote.syscall(syscall_number_for_signalfd4(arch), -1,
                         mask.get().as_int(), sizeof(f->sigmask), f->flags);
    } else if (f->type == OpenFile::EPOLL) {
      r = remote.syscall(syscall_number_for_epoll_create1(arch), f->flags);
    } else {
      AutoRestoreMem path_mem(remote, f->path.c_str());
      r = remote.syscall(openat_nr, AT_FDCWD, path_mem.get().as_int(),
                         f->flags & ~(O_CREAT | O_TRUNC | O_EXCL), 0);
    }

    if (r < 0) {
      LOG(error) << "openat(" << f->path << ") -> " << r;
      ok = false;
      break;
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

    if (remote.syscall(close_nr, r) < 0) {
      LOG(error) << "close(" << r << ") failed";
      ok = false;
      break;
    }

    temporary[f] = (int)tmp;
    temp_fds.insert((int)tmp);

    if (f->offset >= 0) {
      long pos = remote.syscall(syscall_number_for_lseek(arch), tmp, f->offset, SEEK_SET);

      if (pos != f->offset) {
        LOG(error) << "lseek failed: " << pos;
        ok = false;
        break;
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
    fprintf(stderr, "[FdModel] missing parent table: %d\n",
            parent->rec_tid);
    abort();
  }

  ModelFdTablePtr child_table =
      (flags & CLONE_FILES)
          ? it->second
          : std::make_shared<ModelFdTable>(*it->second);

  task_tables[child->rec_tid] = child_table;

  fprintf(stderr,
          "[FdModel] fork parent=%d child=%d shared=%d fds=%zu\n",
          parent->rec_tid,
          child->rec_tid,
          !!(flags & CLONE_FILES),
          child_table->fds.size());
}

const std::map<int, FdModel::OpenFilePtr>&
FdModel::fds(Task* t) const {
  return task_tables.at(t->rec_tid)->fds;
}

} // namespace rr
