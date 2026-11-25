# hpobs — hot-path observer

Watch functions in a stopped-and-steppable target: count entries, pair
returns, dump memory ranges at hits, and single-step one call while logging
every memory access. The target is anything that implements `hpobs::Target`
(read memory, read registers, list mappings, breakpoints, single-step):

- `PtraceTarget` — a live process (`hpobs-trace` CLI)
- `RrTaskTarget` — a task of an rr replay (lives in crriu)
- a gdb remote stub (QEMU `-s`, KVM guests) — planned

Build: `cmake -S . -B build && cmake --build build`. Access tracing (`-x`)
needs capstone (`capstone-devel`); without it the rest still builds.

    hpobs-trace -w foo -w bar -e -v -- ./prog args
    hpobs-trace -w foo -d buf:0x555555558040:128:2 -o out -- setarch x86_64 -R ./prog
    hpobs-trace -x foo:3 -o out -- ./prog
