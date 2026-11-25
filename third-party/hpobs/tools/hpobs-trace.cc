/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

// hpobs-trace: run a command under ptrace and watch functions in it.
//
//   hpobs-trace [-w SYM]... [-e] [-x SYM[:EVERY]]... [-d NAME:ADDR:LEN[:EVERY[:FROM]]]...
//               [-o DIR] [-v] -- CMD [ARG]...
//
// The same watch/dump/access machinery `rr detach` runs on a replay, here on
// a live process. Prints a hit count per watched symbol at exit.

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <map>
#include <string>
#include <vector>

#include "hpobs/access_trace.h"
#include "hpobs/log.h"
#include "hpobs/ptrace_target.h"
#include "hpobs/symbols.h"
#include "hpobs/watch.h"

using namespace std;
using namespace hpobs;

static void report_return(PtraceTarget& t, Watch& watch, const PendingReturn& pr, bool verbose) {
  if (verbose) {
    fprintf(stderr, "ret %s #%" PRId64 " rax %#" PRIx64 "\n", pr.sym.c_str(), pr.n, t.regs().ax());
  }
  watch.dump(t, pr.sym, pr.n, ".exit");
}

static void usage() {
  fprintf(stderr,
          "usage: hpobs-trace [-w SYM]... [-e] [-x SYM[:EVERY]]...\n"
          "                   [-d NAME:ADDR:LEN[:EVERY[:FROM]]]... [-o DIR] [-v] -- CMD [ARG]...\n"
          "  -w SYM        count entries of SYM (breakpoint at its .symtab address)\n"
          "  -e            also stop where each watched call returns; log the return value\n"
          "  -x SYM[:N]    single-step every N-th call of SYM to its return, logging each\n"
          "                memory read/write to DIR/access.SYM.<hit>.txt\n"
          "  -d SPEC       dump LEN bytes at ADDR at every EVERY-th hit (from hit FROM)\n"
          "                of any watched SYM to DIR/NAME.SYM.<hit>.bin\n"
          "  -o DIR        output directory (default .)\n"
          "  -v            log every hit and return to stderr\n");
  exit(2);
}

int main(int argc, char** argv) {
  set_log_prefix("hpobs-trace");
  Watch watch;
  watch.dump_dir = ".";
  bool verbose = false;
  int opt;
  while ((opt = getopt(argc, argv, "+w:ex:d:o:v")) != -1) {
    switch (opt) {
      case 'w':
        watch.add_symbol(optarg);
        break;
      case 'e':
        watch.track_exits = true;
        break;
      case 'x': {
        string spec = optarg;
        int64_t every = 1;
        size_t colon = spec.rfind(':');
        if (colon != string::npos && colon > 2) {
          every = strtoll(spec.c_str() + colon + 1, nullptr, 10);
          spec = spec.substr(0, colon);
        }
        if (every < 1) {
          every = 1;
        }
        watch.add_symbol(spec);
        watch.access_every[spec] = every;
        break;
      }
      case 'd': {
        Dump d;
        if (!parse_dump(optarg, &d)) {
          usage();
        }
        watch.dumps.push_back(d);
        break;
      }
      case 'o':
        watch.dump_dir = optarg;
        break;
      case 'v':
        verbose = true;
        break;
      default:
        usage();
    }
  }
  if (optind >= argc || watch.symbols.empty()) {
    usage();
  }
  if (!watch.access_every.empty() && !trace_access_supported()) {
    logf("-x needs capstone (rebuild with capstone-devel installed)");
    return 2;
  }

  unique_ptr<PtraceTarget> t = PtraceTarget::spawn(argv + optind);
  if (!t) {
    return 1;
  }

  while (true) {
    watch.resolve(*t);
    bool armed = watch.arm(*t);
    PtraceTarget::Stop stop = t->cont();
    if (armed) {
      watch.disarm(*t);
    }
    if (stop.kind == PtraceTarget::StopKind::Exited) {
      break;
    }
    if (stop.kind == PtraceTarget::StopKind::Exec || stop.kind == PtraceTarget::StopKind::Signal) {
      continue;  // nothing of ours; signal is redelivered
    }

    // Breakpoint: a watched entry, or the return of a watched call.
    PendingReturn pr;
    const string* sym = watch.symbol_at(stop.addr);
    if (sym) {
      int64_t n = watch.record_hit(*sym);
      watch.dump(*t, *sym, n);
      if (watch.track_exits) {
        watch.expect_return(*t, *sym, n);
      }
      if (verbose) {
        Regs u = t->regs();
        fprintf(stderr,
                "hit %s #%" PRId64 " tid %d rdi %#" PRIx64 " rsi %#" PRIx64 " rdx %#" PRIx64 "\n",
                sym->c_str(), n, t->tid(), u.arg(0), u.arg(1), u.arg(2));
      }
      auto ae = watch.access_every.find(*sym);
      if (ae != watch.access_every.end() && n % ae->second == 0) {
        int64_t steps = 0;
        string path;
        bool ok = trace_access(*t, *sym, n, watch.dump_dir, &steps, &path);
        if (verbose) {
          fprintf(stderr, "access %s #%" PRId64 ": %" PRId64 " instructions -> %s\n", sym->c_str(),
                  n, steps, path.c_str());
        }
        if (!ok) {
          break;
        }
        if (watch.take_return(*t, &pr)) {  // we stepped onto the return
          report_return(*t, watch, pr, verbose);
        }
      }
    } else if (watch.take_return(*t, &pr)) {
      report_return(*t, watch, pr, verbose);
    }
  }

  for (const string& s : watch.symbols) {
    int64_t n = watch.hits_of(s);
    printf("%s: %" PRId64 " hit%s%s\n", s.c_str(), n, n == 1 ? "" : "s",
           watch.resolved(s) ? "" : " (never resolved)");
  }
  int code = t->exit_code();
  if (code < 0) {
    fprintf(stderr, "%s: killed by signal %d\n", log_prefix(), -code);
    return 128 - code;
  }
  return code;
}
