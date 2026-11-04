/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "FdModel.h"

#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <limits>
#include <set>

#include "AutoRemoteSyscalls.h"
#include "Event.h"
#include "Task.h"
#include "TraceFrame.h"
#include "kernel_abi.h"
#include "log.h"

using namespace std;

namespace rr {

string FdModel::resolve(Task* t, int dirfd, uintptr_t path_ptr) {
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
    if (ret == 0)
      table.erase((int)a0);
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
    if (ret > 0 && table.count((int)a0) &&
      table[(int)a0]->offset >= 0)
      table[(int)a0]->offset += ret;

  } else if (no == syscall_number_for_write(arch)) {
    if (ret > 0 && table.count((int)a0)) {
      auto& f = table[(int)a0];

      if (f->flags & O_APPEND)
        f->offset = -1;
      else if (f->offset >= 0)
        f->offset += ret;
    }
  } else if (no == syscall_number_for_chdir(arch)) {
    if (ret == 0) cwd = resolve(t, AT_FDCWD, (uintptr_t)a0);
  }
  // TODO: fcntl(F_DUPFD*), pread/pwrite (no offset change), readv/writev,
  //       openat2, pipe/socket (kind != regular file), fchdir.
}

bool FdModel::materialize(Task* t) {
  if (table.empty())
    return true;

  // Validate offsets before modifying the tracee's FD table.
  for (const auto& entry : table) {
    int fd = entry.first;
    const auto& file = entry.second;

    if (file->offset < 0) {
      LOG(error) << "Cannot restore fd " << fd
        << ": file offset is unknown";
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

    AutoRestoreMem path_mem(remote, f->path.c_str());

    long r = remote.syscall(
      openat_nr,
      AT_FDCWD,
      path_mem.get().as_int(),
      f->flags & ~(O_CREAT | O_TRUNC | O_EXCL),
      0);

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
      long pos = remote.syscall(
        syscall_number_for_lseek(arch),
        tmp, f->offset, SEEK_SET);

      if (pos != f->offset) {
        LOG(error) << "lseek failed: " << pos;
        ok = false;
        break;
      }
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

} // namespace rr
