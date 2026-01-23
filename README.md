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

## Optimizing existing binaries

Currently peepopt only does simple replacements, e.g., shifts, that can be done without increasing or decreasing the number of instruction bytes.
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

## Usage

* `peepopt --dry-run program_file`
  - Show which replacements peepopt would do
* `peepopt [--verbose] program_file`
  - Optimize the input binary with replacement instructions

## Future directions

* [10-15 byte no-ops](https://reviews.llvm.org/D75945) - optimal on Sandy Bridge and newer only but Atom and Zen perform poorly
* [APX](https://en.wikipedia.org/wiki/X86#APX) - expanded three-operand and no flag instructions, supported by Panther Lake and newer processors
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
