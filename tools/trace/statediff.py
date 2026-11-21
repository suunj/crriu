#!/usr/bin/env python3
"""Diff successive -D dumps: which bytes/fields the program changed between hits.

usage: statediff.py DUMPDIR NAME [--layout PTYPE_O_FILE] [--top N]
"""
import os, re, sys, argparse
ap = argparse.ArgumentParser()
ap.add_argument("dir"); ap.add_argument("name")
ap.add_argument("--layout", help="output of gdb 'ptype /o struct X'")
ap.add_argument("--top", type=int, default=40)
a = ap.parse_args()

pat = re.compile(r"^%s\.(.+)\.(\d+)\.bin$" % re.escape(a.name))
files = []
for f in os.listdir(a.dir):
    m = pat.match(f)
    if m: files.append((m.group(1), int(m.group(2)), f))
files.sort(key=lambda x: (x[0], x[1]))
if len(files) < 2: sys.exit("need at least two dumps")

fields = []   # (offset, size, name)
if a.layout:
    fre = re.compile(r"/\*\s*(\d+)(?::\s*\d+)?\s*\|\s*(\d+)\s*\*/\s*(.*?)\s*;")
    for line in open(a.layout):
        m = fre.search(line)
        if not m: continue
        off, size, decl = int(m.group(1)), int(m.group(2)), m.group(3)
        nm = re.sub(r"\[.*", "", decl.split()[-1]).lstrip("*")
        if "{" in decl: continue
        fields.append((off, size, nm))
    fields.sort()

def field_of(off):
    lo, hi = 0, len(fields)
    best = None
    for f in fields:
        if f[0] <= off < f[0] + f[1]: best = f
    return best

prev = None; pairs = 0
byte_changes = {}
field_changes = {}
for sym, n, f in files:
    data = open(os.path.join(a.dir, f), "rb").read()
    if prev is not None and len(prev) == len(data):
        pairs += 1
        touched = set()
        for i, (x, y) in enumerate(zip(prev, data)):
            if x != y:
                byte_changes[i] = byte_changes.get(i, 0) + 1
                fl = field_of(i)
                touched.add(fl[2] if fl else "off+%#x" % i)
        for t in touched: field_changes[t] = field_changes.get(t, 0) + 1
    prev = data

print("%d dumps, %d consecutive pairs, %d bytes each" % (len(files), pairs, len(prev)))
print("%-28s %8s  %s" % ("field", "changed", "of pairs"))
for name, c in sorted(field_changes.items(), key=lambda kv: -kv[1])[:a.top]:
    print("%-28s %8d  %5.1f%%" % (name, c, 100.0 * c / pairs))
if fields:
    never = [f[2] for f in fields if f[2] not in field_changes]
    print("\nunchanged across all pairs (%d fields): %s" % (len(never), " ".join(never[:60])))
