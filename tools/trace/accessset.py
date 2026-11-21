#!/usr/bin/env python3
"""Summarize `rr detach -x` access logs as read/write field sets.

  accessset.py ACCESS.txt... --region NAME:ADDR:LEN[:LAYOUT]

LAYOUT is a `ptype /o` dump of the struct at ADDR; with it, each access
inside the region is mapped to the innermost member covering it.
Accesses within 64 KiB below / 4 KiB above the entry sp are reported as 'stack'.
"""
import argparse, re, sys
from collections import defaultdict

MEMBER = re.compile(r'^\s*/\*\s*(\d+)(?::\s*\d+)?\s*\|\s*(\d+)\s*\*/\s*(.*?);')

def load_layout(path):
    members = []                                  # (off, size, name)
    for line in open(path):
        m = MEMBER.match(line)
        if not m:
            continue
        off, size, decl = int(m[1]), int(m[2]), m[3]
        decl = decl.split('{')[0]                 # drop 'struct {' heads
        ids = re.findall(r'[A-Za-z_]\w*', decl.split('[')[0])
        if not ids:
            continue
        members.append((off, size, ids[-1]))
    return members

def field_of(members, off):
    best = None
    for moff, msize, name in members:
        if moff <= off < moff + msize and (best is None or msize < best[1]):
            best = (moff, msize, name)
    if best is None:
        return '+%d' % off
    moff, msize, name = best
    return name if msize <= 8 else '%s[+%d]' % (name, off - moff)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('logs', nargs='+')
    ap.add_argument('--region', action='append', default=[],
                    help='NAME:ADDR:LEN[:LAYOUT]')
    a = ap.parse_args()
    regions = []
    for spec in a.region:
        parts = spec.split(':')
        name, addr, ln = parts[0], int(parts[1], 0), int(parts[2], 0)
        members = load_layout(parts[3]) if len(parts) > 3 else []
        regions.append((name, addr, ln, members))

    for path in a.logs:
        sp0 = None
        reads, writes = defaultdict(int), defaultdict(int)
        n = 0
        for line in open(path):
            if line.startswith('#'):
                m = re.search(r'entry sp (0x[0-9a-f]+)', line)
                if m:
                    sp0 = int(m[1], 16)
                continue
            f = line.split()
            if len(f) < 4:
                continue
            ip, rw, addr, size = f[0], f[1], int(f[2], 0), int(f[3])
            n += 1
            key = None
            for name, base, ln, members in regions:
                if base <= addr < base + ln:
                    key = '%s.%s' % (name, field_of(members, addr - base))
                    break
            if key is None:
                if sp0 is not None and sp0 - 65536 <= addr < sp0 + 4096:
                    key = 'stack'
                else:
                    key = 'other %#x' % addr
            (reads if rw == 'R' else writes)[key] += 1
        print('== %s  (%d accesses)' % (path, n))
        for title, d in (('READ', reads), ('WRITE', writes)):
            print('  %s (%d distinct):' % (title, len(d)))
            for k, c in sorted(d.items(), key=lambda kv: (-kv[1], kv[0])):
                print('    %6d  %s' % (c, k))

if __name__ == '__main__':
    main()
