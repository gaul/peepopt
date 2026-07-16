# peepopt 🐣

peepopt recompiles x86-64 binaries using peephole optimization to take advantage of instructions available in newer processors.
This improves performance and reduces power consumption in some situations.

## Background

When compiling a program one must decide which processor family to target, e.g., x86-64, ARMv8.
They may further specialize to a subset of processors, e.g., Intel Alder Lake or newer.
Most Linux distributions compile binaries for a least-common denominator profile, e.g., [x86-64 v1 in Fedora](https://fedoraproject.org/wiki/Changes/Optimized_Binaries_for_the_AMD64_Architecture), [x86-64 v3 in RHEL 10](https://developers.redhat.com/articles/2024/01/02/exploring-x86-64-v3-red-hat-enterprise-linux-10).
Some distributions like Gentoo can compile from source to target a more specific processor and unlock additional performance.
peepopt applies inexpensive peephole optimizations that reclaim some of this performance without expensive full-program compilation.

## Shift left example

Consider a C function:

```c
uint32_t shift(uint32_t x, uint32_t y)
{
    return x << y;
}
```

### Shifting left with x86-64-v1

The `sall` instruction only takes two operands which requires `movl` instructions to set up the input registers:

```
89F8           movl %edi,%eax
89F1           movl %esi,%ecx
D3E0           sall %cl,%eax
C3             ret
```

### Shifting left with x86-64-v3 (BMI2)

The `shlx` instruction takes three operands which allows more flexibility and does not require `movl`s:

```
C4E249F7C7     shlx %esi,%edi,%eax
C3             ret
```

Note that this is not equivalent to the former example since `sall` explicitly writes to `%cl` and implicitly writes to `EFLAGS`.
When rewriting instructions peepopt examines subsequent instructions to ensure that they would not observe the replacement.

## Transformations

peepopt currently implements three always-on families of rewrites within the x86-64-v3 feature level (BMI1, BMI2, AVX), plus an opt-in APX family (`-m apx`).
Every replacement fits within the bytes of the original instructions — shorter replacements are padded with no-ops — and is refused when a branch targets the interior of the rewritten range.
Branch targets are gathered from PC-relative direct branches, `switch` jump tables in `.rodata`/`.data.rel.ro`, relocation-derived code pointers (RELA and RELR), and exception landing pads (`.eh_frame`/`.gcc_except_table`), so table dispatch, function-pointer entry points, and unwinder entry points are protected too (see LIMITATIONS.md for what remains invisible).

### Variable shifts: SHL/SHR/SAR → SHLX/SHRX/SARX (BMI2)

The legacy shifts take a variable count only in `%cl`, so compilers emit a `mov` to stage it:

```
4889F1         mov %rsi,%rcx
48D3E0         shl %cl,%rax
```

The BMI2 shifts take the count from any register and do not write `EFLAGS`:

```
C4E2C9F7C0     shlx %rsi,%rax,%rax
```

After the rewrite `%rcx` no longer holds the count and `EFLAGS` no longer holds the shift's result flags, so peepopt scans forward to prove both are overwritten before any read.
The pass can also absorb a second `mov` supplying the shifted value — producing the fully three-operand form shown in the example above — and when the count-setting `mov` is not adjacent to the shift it repacks the instructions between them downward so the pair becomes contiguous.

### NOT + AND → ANDN (BMI1)

An and-not computation `dst = ~a & b` requires two instructions:

```
48F7D7         not %rdi
4821F7         and %rsi,%rdi
```

`andn` computes it in one:

```
C4E2C0F2FE     andn %rsi,%rdi,%rdi
```

Both orderings are handled.
Inverting the AND destination (shown) leaves no register holding a stale value.
Inverting the AND source (`not %rsi; and %rsi,%rdi` → `andn %rdi,%rsi,%rdi`) leaves `%rsi` holding its original rather than inverted value, so it is only rewritten when `%rsi` is overwritten before any later read.
In both cases `andn` leaves `PF` undefined where `and` defines it, so `PF` must also be dead.

### SSE copy + op → AVX three-operand VEX form

Two-operand SSE instructions destroy their first source, so compilers copy values that are still needed:

```
660F28D0       movapd %xmm0,%xmm2
660F58D1       addpd %xmm1,%xmm2
```

The VEX-encoded forms of the same operations take a separate destination, folding the copy away:

```
C5F958D1       vaddpd %xmm1,%xmm0,%xmm2
```

93 scalar and packed opcodes are mapped: floating-point arithmetic and min/max, logic, integer arithmetic with and without saturation, multiplies, averages, compares, packs and unpacks, and shifts.
A memory source folds into the VEX form the same way (`movapd %xmm4,%xmm5; addsd 8(%rax),%xmm5` → `vaddsd 8(%rax),%xmm4,%xmm5`), recomputing RIP-relative displacements for the new instruction location.
Unlike the integer rewrites this needs no forward analysis: neither instruction touches `EFLAGS` and every register holds the same value afterward.

### MOV + integer op → APX NDD three-operand form (`-m apx`)

Two-operand integer instructions destroy their first source, so compilers copy values that are still needed:

```
4889F0         mov %rsi,%rax
4801C8         add %rcx,%rax
```

[Intel APX](https://en.wikipedia.org/wiki/X86#APX) promotes the legacy integer ops to EVEX (map 4) forms with a *new data destination*, folding the copy away:

```
62F4FC1801CE   add %rcx,%rsi,%rax
```

ADD, ADC, SUB, SBB, AND, OR, and XOR are rewritten with register, memory, or immediate sources; two-operand IMUL and the sixteen CMOVcc with register or memory sources (their promoted immediate forms do not exist).
NEG, NOT, INC, and DEC fold the same way into two-operand promoted forms (`mov %rdi,%rax; neg %rax` → `neg %rdi,%rax`), and SHL, SHR, SAR, ROL, and ROR fold with their immediate or `%cl` count carried over.
The promoted forms write `EFLAGS` exactly like their legacy encodings — INC/DEC still preserve CF and a zero shift count still writes nothing — so unlike the SHLX rewrite no forward flag analysis is needed.
A `%cl`-count shift whose destination is in the RCX family is refused: the legacy sequence shifts by the count the copy itself just wrote.
Like the VEX rewrite this needs no forward analysis: the promoted forms with `NF=0` read and write `EFLAGS` exactly like their legacy encodings (ADC/SBB consume the same incoming carry), every source register keeps its value, and the destination receives the identical result.
The MOV must write exactly the register the op destroys: a narrower copy feeding a wider op relies on the MOV's zero extension, and 8/16-bit ops are excluded because their promoted forms zero the rest of the destination.
A memory address that reads the copy's destination would compute from a stale value once the MOV is folded away, so those sites are refused.

A memory-*source* copy folds symmetrically, moving the load into the fused instruction (`mov (%rdi),%rax; add %rsi,%rax` → `add (%rdi),%rsi,%rax`):

```
488B07         mov (%rdi),%rax
4801F0         add %rsi,%rax
```

```
62F4FC180337   add (%rdi),%rsi,%rax
```

With a register second source the r/m slot is taken, so the op must be commutative — SUB and SBB are refused — or a CMOVcc, which folds with its condition inverted (both the legacy pair and the promoted CMOVcc access memory whatever the condition).
Immediate, unary, and shift ops keep the loaded value as the first operand instead, so all of them fold, SUB and SBB included.
Because the address is computed inside the fused instruction, it may even read the destination (`mov (%rax),%rax; add %rsi,%rax` is fine) — the stale-address refusal only applies in the other direction.
The 64-bit register pair and the EVEX form are both six bytes, an exact fit; REX-less 32-bit pairs are two bytes too short and stay legacy.

A related fuse rewrites Boolean materialization: `setcc %al; movzx %al,%eax` becomes the promoted zero-upper SETcc, which writes the condition byte and zeroes bits 63:8 exactly as the 32- or 64-bit MOVZX did:

```
0F94C0         setz %al
0FB6C0         movzx %al,%eax
```

```
62F47F1844C0   setzuz %al
```

The shortest legacy pair and the EVEX form are both six bytes, so every site fits.
High-byte sources (`%ah`) cannot be EVEX-encoded and a 16-bit MOVZX destination preserves upper bits that ZU zeroes, so both are refused.

Because APX requires very new processors (Panther Lake / Diamond Rapids and later), this family is opt-in via `-m apx` and is validated under the [Intel Software Development Emulator](https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html): `make test-apx` rewrites an assembly fixture, diffs its output under `sde64 -dmr` against a native baseline, and checks SDE's instruction-mix histogram to prove NDD instructions actually executed.

## Optimizing existing binaries

Currently peepopt only does the simple replacements described above that can be done without increasing or decreasing the number of instruction bytes.
Unused bytes are padded with no-ops which may seem wasteful but processors discard them early during execution.
Further the instructions represent fewer and simpler micro-operations which increase instruction cache hit rates and reduce execution overhead.

## Benchmarks

Anecdotally using the x86-64-v3 profile improves performance by a few percent:

* [Arch x86-64v3 proposal](https://gitlab.archlinux.org/archlinux/rfcs/-/blob/master/rfcs/0002-x86-64-v3-microarchitecture.md)
  - Claims 9.9% improvement for Firefox
* [CentOS investigation](https://blog.centos.org/2023/08/centos-isa-sig-performance-investigation/)
* [Ubuntu x86-64-v3 packages](https://discourse.ubuntu.com/t/introducing-architecture-variants-amd64v3-now-available-in-ubuntu-25-10/71312)
  - Claims 1% improvement for most packages and more for numerical programs
  - [Mixed results for desktops](https://www.phoronix.com/review/ubuntu-2510-amd64v3)
  - [More positive results for servers](https://www.phoronix.com/news/Ubuntu-Server-25.10-amd64v3)

TODO: run benchmarks for Firefox and GCC

## Compilation

First install the [Intel x86 encoder decoder](https://github.com/intelxed/xed):

```
git clone https://github.com/intelxed/xed.git xed
git clone https://github.com/intelxed/mbuild.git mbuild
cd xed
./mfile.py install --install-dir=kits/xed-install
```

Next build peepopt:

```
git clone https://github.com/gaul/peepopt.git peepopt
cd peepopt
XED_PATH=/path/to/xed make all
```

Run the unit tests with `make test`.
The APX end-to-end test additionally needs an [Intel SDE](https://www.intel.com/content/www/us/en/developer/articles/tool/software-development-emulator.html) kit:

```
XED_PATH=/path/to/xed SDE_PATH=/path/to/sde make test-apx
```

## Usage

* `peepopt --dry-run program_file`
  - Show which replacements peepopt would do
* `peepopt [--verbose] program_file`
  - Optimize the input binary with replacement instructions
* `peepopt --dry-run --stats program_file`
  - Also print a histogram of why each candidate site was or was not rewritten
* `peepopt -m apx program_file`
  - Also apply the APX rewrites; the output requires an APX processor or emulator

## Future directions

* [10-15 byte no-ops](https://reviews.llvm.org/D75945) - optimal on Sandy Bridge and newer only but Atom and Zen perform poorly
* more [APX](https://en.wikipedia.org/wiki/X86#APX) - no-flag (NF) variants and extended GPRs (R16-R31)
  - measured dead ends: CFCMOV/CCMP branch elimination (a rel8 `jcc` plus the guarded op is always one byte short of the EVEX form), PUSH2/POP2 (never fits), JMPABS (needs link-time-unknown GOT values)
* [BMI](https://en.wikipedia.org/wiki/X86_Bit_manipulation_instruction_set) - more flexible bit manipulations
* FSRM - improve memory copies on Ice Lake and newer processors
  - difficult replacement due more complicated register usage
* inline [compiler builtins](https://gcc.gnu.org/onlinedocs/gcc/Bit-Operation-Builtins.html), e.g., popcount
* inline [indirect functions](https://sourceware.org/glibc/wiki/GNU_IFUNC)

### Distributions

peepopt could automatically run during distribution package installs.
This will require plugins for package managers like `apt` and `dnf`.

## License

Copyright (C) 2026 Andrew Gaul

Licensed under the Apache License, Version 2.0
