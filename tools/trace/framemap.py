#!/usr/bin/env python3
"""framemap.py TRACE [RANGE] [--layout T]

One line per frame: syscall with pointer arguments named by mapping, the
result, and every memory write the frame made (region+offset, bytes).
--layout T prints the mappings as of frame T with write counts so far.
Reads `rr dump -d -p`; RR env var selects the binary."""
import os, re, subprocess, sys

RR = os.environ.get("RR", "rr")

HDR = re.compile(r"global_time:(\d+), event:`([^']*)' (?:\(state:(\w+)\) )?tid:(\d+), ticks:(\d+)")
MAP = re.compile(r'\{ map_file:"([^"]*)", addr:0x([0-9a-f]+), length:0x([0-9a-f]+), prot_flags:"([^"]*)", file_offset:0x([0-9a-f]+)')
DAT = re.compile(r"\{ tid:(\d+), addr:0x([0-9a-f]+), length:0x([0-9a-f]+) \}")
REG = re.compile(r"(\w+):0x([0-9a-f]+)")

class Mapping:
    def __init__(self, name, start, length, prot, foff):
        self.name, self.start, self.end, self.prot, self.foff = name, start, start + length, prot, foff
        self.writes = 0; self.bytes = 0; self.frames = []   # (frame, event, size)
    def label(self):
        n = os.path.basename(self.name) or "anon"
        if n == "<ZERO>": n = "anon"
        return n

class Layout:
    def __init__(self): self.maps = []
    def add(self, m):                      # new mapping replaces what it overlaps
        self.maps = [x for x in self.maps if x.end <= m.start or x.start >= m.end]
        self.maps.append(m); self.maps.sort(key=lambda x: x.start)
    def find(self, addr):
        for m in self.maps:
            if m.start <= addr < m.end: return m
        return None
    def name(self, addr):
        m = self.find(addr)
        if not m: return "0x%x" % addr
        if m.name.startswith("/"):        # file-relative offset, like objdump/nm
            return "%s+0x%x" % (m.label(), addr - m.start + m.foff)
        return "%s+0x%x" % (m.label(), addr - m.start)

STAT = [("st_dev",8),("st_ino",8),("st_nlink",8),("st_mode",4),("st_uid",4),("st_gid",4),
        ("__pad0",4),("st_rdev",8),("st_size",8),("st_blksize",8),("st_blocks",8),
        ("st_atime",8),("st_atime_nsec",8),("st_mtime",8),("st_mtime_nsec",8),
        ("st_ctime",8),("st_ctime_nsec",8)]
RLIMIT = [("rlim_cur",8),("rlim_max",8)]
DECODE = {"fstat": ("struct stat", STAT), "stat": ("struct stat", STAT), "lstat": ("struct stat", STAT),
          "newfstatat": ("struct stat", STAT), "prlimit64": ("struct rlimit", RLIMIT),
          "getrlimit": ("struct rlimit", RLIMIT)}

def rows(data, sc, where):   # where: "[stack]+0x1e600" style base of this write
    """Decode a write: named fields when the syscall's result struct is known,
    else 8-byte little-endian words with ascii."""
    out = []
    if sc in DECODE:
        name, fields = DECODE[sc]
        off = 0
        for fname, size in fields:
            if off + size > len(data): break
            chunk = data[off:off + size]
            out.append("%-24s %-23s  %-14s = %d" % (where_plus(where, off), " ".join("%02x" % b for b in chunk), fname,
                                                      int.from_bytes(chunk, "little")))
            off += size
        return name, out
    for off in range(0, len(data), 8):
        chunk = data[off:off + 8]
        out.append("%-24s %-23s  %-16s %s" % (where_plus(where, off), " ".join("%02x" % b for b in chunk),
                                            "= %d" % int.from_bytes(chunk, "little"), ascii(chunk)))
    return None, out

def where_plus(where, off):
    """"[stack]+0x1e600" + 8 -> "[stack]+0x1e608"; a bare "0x..." address likewise."""
    base, _, hexoff = where.rpartition("+")
    if hexoff.startswith("0x"):
        return "%s+0x%x" % (base, int(hexoff, 16) + off)
    return "0x%x" % (int(where, 16) + off)

REGS = ["rip", "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "rsp", "rbp"]

def reg_value(name, v, layout):
    if name == "orig_rax":
        return "-" if v == (1 << 64) - 1 else str(v)
    if layout.find(v):                      # pointer into a known mapping
        return layout.name(v)
    if v >= 1 << 63:                        # negative (errno / -ENOSYS)
        return str(v - (1 << 64))
    return hex(v) if v > 0xffff else str(v)

def reg_block(regs, prev, layout):
    cells = []
    for r in REGS:
        if r not in regs: continue
        mark = "*" if prev and prev.get(r) != regs[r] else ""
        cells.append("%s%s=%s" % (mark, r, reg_value(r, regs[r], layout)))
    return "  ".join(cells)

def ascii(bs): return "".join(chr(b) if 32 <= b < 127 else "." for b in bs)

def main():
    args = sys.argv[1:]
    layout_at = None
    if "--layout" in args:
        i = args.index("--layout"); spec = args[i + 1]; del args[i:i + 2]
        a, _, b = spec.partition("-")
        layout_lo, layout_at = (int(a), int(b)) if b else (0, int(a))   # LO-HI counts that range only
    show_regs = "--regs" in args
    if show_regs: args.remove("--regs")
    trace = args[0]
    lo, hi = 0, 1 << 62                   # output range; the whole trace is read for the layout
    if len(args) > 1:
        a, _, b = args[1].partition("-"); lo = int(a); hi = int(b) if b else lo
    if layout_at is not None:
        lo, hi = layout_lo, layout_at     # only writes in this range are counted
    out = subprocess.run([RR, "dump", "-d", "-p", trace], capture_output=True, text=True, check=True).stdout
    layout = Layout()
    frame = None; regs = {}; writes = []; pending = None
    prev_regs = [{}]
    lines = []
    def flush():
        if frame is None: return
        t, ev, state, tid, ticks = frame
        if not (lo <= t <= hi):
            for addr, data, size in writes:   # --layout: count writes in its own range
                m = layout.find(addr)
                if m and layout_at is not None and layout_lo <= t <= layout_at:
                    m.writes += 1; m.bytes += size; m.frames.append((t, ev, size))
            return
        sc = ev.split(": ", 1)[1] if ev.startswith("SYSCALL") else ev
        if state == "ENTERING_SYSCALL":
            a = [regs.get("rdi", 0), regs.get("rsi", 0), regs.get("rdx", 0)]
            fa = [layout.name(x) if layout.find(x) else str(x) for x in a]
            line = "%-5s %s(%s)" % (t, sc, ", ".join(fa))
        elif state == "EXITING_SYSCALL":
            r = regs.get("rax", 0)
            r = r - (1 << 64) if r >= 1 << 63 else r
            line = "%-5s   = %d" % (t, r)
        else:
            line = "%-5s %s" % (t, ev)
        if show_regs and regs:
            line = "%-44s| %s" % (line, reg_block(regs, prev_regs[0], layout))
            prev_regs[0] = dict(regs)
        for addr, data, size in writes:
            m = layout.find(addr)
            if m: m.writes += 1; m.bytes += size; m.frames.append((t, ev, size))
            name, rs = rows(data, sc, layout.name(addr))
            line += "\n%-5s   wrote %s +%d%s" % ("", layout.name(addr), size, "  (%s)" % name if name else "")
            limit = len(rs) if ("-x" in sys.argv or name) else 4
            line += "".join("\n      " + r for r in rs[:limit])
            if len(rs) > limit: line += "\n        ... %d more rows (-x)" % (len(rs) - limit)
        lines.append(line)
    for raw in out.splitlines():
        s = raw.strip()
        h = HDR.search(s)
        if h:
            flush(); frame = (int(h[1]), h[2], h[3], int(h[4]), int(h[5])); regs = {}; writes = []; pending = None
            if layout_at is not None and frame[0] > layout_at: break
            continue
        if s.startswith("rax:"):
            regs = {k: int(v, 16) for k, v in REG.findall(s)}; continue
        m = MAP.search(s)
        if m:
            layout.add(Mapping(m[1], int(m[2], 16), int(m[3], 16), m[4], int(m[5], 16))); continue
        d = DAT.search(s)
        if d:
            pending = [int(d[2], 16), bytearray(), int(d[3], 16)]; writes.append(pending); continue
        if pending is not None and re.fullmatch(r"([0-9a-f]{2} ?)+(\.\.\..*)?", s):
            pending[1] += bytes.fromhex(s.split("...")[0].replace(" ", ""))
    flush()
    if layout_at is not None:
        print("layout after frame %d (regions written in %d-%d; -a for all):" % (layout_at, layout_lo, layout_at))
        for m in layout.maps:
            if m.writes == 0 and "-a" not in sys.argv: continue
            print("  %016x-%016x %s %-40s writes %d (%d bytes)" % (m.start, m.end, m.prot, m.label() if not m.name.startswith("/") else m.name, m.writes, m.bytes))
            if "-v" in sys.argv:
                for t, ev, size in m.frames:
                    print("      frame %-5d %-22s %d bytes" % (t, ev.replace("SYSCALL: ", ""), size))
            else:                           # one line per (frame, event)
                grouped = []
                for t, ev, size in m.frames:
                    if grouped and grouped[-1][0] == t and grouped[-1][1] == ev:
                        grouped[-1][2] += 1; grouped[-1][3] += size
                    else:
                        grouped.append([t, ev, 1, size])
                print("      " + "  ".join("%d:%s%s(%d)" % (t, ev.replace("SYSCALL: ", ""),
                      "x%d" % n if n > 1 else "", b) for t, ev, n, b in grouped))
    else:
        print("\n".join(lines))

main()
