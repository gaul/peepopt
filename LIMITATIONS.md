# Limitations

peepopt performs equal-size rewrites without relocating code.
That keeps it simple and avoids disturbing PC-relative addressing, but it also
bounds what it can safely touch. The rewrites happen on a temporary copy that
atomically replaces the target only after every pass and the boundary
verifier succeed, so a failure or crash leaves the original untouched (at
worst a stray `<file>.peepopt.*` temporary remains after a hard kill). The
replace swaps the inode: hard links to the original keep the old content,
and the target of a symlink — not the symlink itself — is replaced.

* **Indirect branches are covered only when their targets are recoverable.**
  The pre-scan protects, in addition to PC-relative direct branches: `switch`
  jump tables (int32-relative tables in `.rodata`/`.data.rel.ro` reachable
  from a RIP-relative LEA — the clang/gcc PIC lowering — and absolute tables
  referenced by `jmp *table(,%r,8)`), plus relocation-derived code pointers
  (RELATIVE/IRELATIVE RELA addends and RELR slot contents), which covers
  vtables, function pointers, and computed-goto labels in PIE/shared
  objects, plus `.symtab`/`.dynsym` symbol values, which covers named
  mid-function labels and ifunc resolvers, plus `ENDBR64`/`ENDBR32`
  landing sites, which in CET/IBT binaries over-approximate every legal
  indirect target regardless of how it is computed. In binaries built
  *without* IBT, an indirect transfer whose target is computed some other
  way — a table base materialized without a LEA, pointer arithmetic in
  hand-written assembly targeting an unnamed location, JIT dispatch,
  non-PIE absolute pointer tables with no relocations, targets named only
  by stripped symbols — remains invisible.
* **Jump-table extents are heuristic.** Table boundaries are not recorded in
  the binary, so each candidate table is walked until the next candidate
  base, the end of the section, or the first entry that does not land in
  `.text`. This over-approximates (extra marks only suppress rewrites) but
  could in principle under-mark if a LEA elsewhere targets the interior of a
  real jump table — a pattern compilers do not emit, since tables are
  anonymous objects referenced only through their base.
* **Exception landing pads are protected; other EH metadata is not
  updated.** peepopt walks `.eh_frame` FDEs to each function's LSDA in
  `.gcc_except_table` and treats every landing pad as a branch target, so
  rewrites never bury an unwinder entry point. A malformed or unsupported
  `.eh_frame` is a hard error rather than a silent gap. Call-site ranges
  and DWARF CFI programs are not rewritten, which is harmless because
  rewrites preserve instruction span boundaries and never touch the stack
  layout.
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
of hazard above that it does handle. As a final check, every non-dry
run re-decodes each rewritten section and fails if any collected branch
target no longer falls on an instruction boundary (targets already
inside instructions before rewriting are baselined and ignored, since
the conservative target collection over-approximates).
