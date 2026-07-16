# Limitations

peepopt performs equal-size in-place rewrites without relocating code.
That keeps it simple and avoids disturbing PC-relative addressing, but it also
bounds what it can safely touch.

* **Indirect branches are covered only when their targets are recoverable.**
  The pre-scan protects, in addition to PC-relative direct branches: `switch`
  jump tables (int32-relative tables in `.rodata`/`.data.rel.ro` reachable
  from a RIP-relative LEA — the clang/gcc PIC lowering — and absolute tables
  referenced by `jmp *table(,%r,8)`), plus relocation-derived code pointers
  (RELATIVE/IRELATIVE RELA addends and RELR slot contents), which covers
  vtables, function pointers, and computed-goto labels in PIE/shared
  objects. An indirect transfer whose target is computed some other way —
  a table base materialized without a LEA, pointer arithmetic in
  hand-written assembly, JIT dispatch, non-PIE absolute pointer tables with
  no relocations — remains invisible.
* **Jump-table extents are heuristic.** Table boundaries are not recorded in
  the binary, so each candidate table is walked until the next candidate
  base, the end of the section, or the first entry that does not land in
  `.text`. This over-approximates (extra marks only suppress rewrites) but
  could in principle under-mark if a LEA elsewhere targets the interior of a
  real jump table — a pattern compilers do not emit, since tables are
  anonymous objects referenced only through their base.
* **No exception-handling awareness.** `.eh_frame` and `.gcc_except_table`
  describe exception landing pads. peepopt does not parse them, so if a
  landing pad points into an absorbed range, the frame info for that
  function becomes stale.
* **No debug-info updating.** DWARF line tables still point at the original
  instruction boundaries after rewriting. Debuggers may report odd source
  mappings inside rewritten ranges, but unwinding continues to work because
  return addresses are unchanged.
* **Basic-block scoped analysis.** The tool doesn't build a CFG. Shifts
  reachable from multiple predecessors (e.g., at a branch target) can't
  have their MOV1 validated against every predecessor and are typically
  rejected.
* **System V AMD64 ABI assumed.** CALL is treated as clobbering ECX and
  EFLAGS, which is correct for Linux/macOS but not for Windows x64.
  Running the tool on PE binaries would be unsafe without ABI-aware
  clobber sets.

Within these bounds peepopt errs toward refusing a rewrite rather than
performing an unsafe one, and includes soundness tests for the classes
of hazard above that it does handle.
