// Deterministic MOV+op candidates for the APX NDD end-to-end test
// (test-apx.sh). Each body is hand-written so `peepopt -m apx` rewrites a
// known set of sites; nothing here stages a shift count into %rcx, uses
// NOT+AND, or SSE copy+op pairs, so the always-on passes leave these bodies
// alone.

    .text

    .globl apx_add64
    .type apx_add64, @function
apx_add64:
    mov %rdi, %rax
    add %rsi, %rax
    ret

    // Non-commutative: rax = rdi - rsi.
    .globl apx_sub64
    .type apx_sub64, @function
apx_sub64:
    mov %rdi, %rax
    sub %rsi, %rax
    ret

    // Op source == op destination exercises the copy-source substitution.
    .globl apx_add_same
    .type apx_add_same, @function
apx_add_same:
    mov %rdi, %rax
    add %rax, %rax
    ret

    // 32-bit pair whose REX prefixes make it big enough to rewrite.
    .globl apx_xor32_ext
    .type apx_xor32_ext, @function
apx_xor32_ext:
    mov %edi, %r8d
    xor %esi, %r8d
    mov %r8d, %eax
    ret

    // Negative control: a REX-less 32-bit pair is too short to rewrite and
    // must keep behaving identically.
    .globl apx_add32_norex
    .type apx_add32_norex, @function
apx_add32_norex:
    mov %edi, %eax
    add %esi, %eax
    ret

    // Memory source folds into the EVEX r/m slot: rax = rsi + (%rdi).
    .globl apx_mem64
    .type apx_mem64, @function
apx_mem64:
    mov %rsi, %rax
    add (%rdi), %rax
    ret

    // The rewritten ADC must consume the CF produced just before it.
    .globl apx_adc64
    .type apx_adc64, @function
apx_adc64:
    add %rsi, %rdi
    mov %rdx, %rax
    adc %rcx, %rax
    ret

    // The rewritten ADD must still produce CF (NF=0): dl = carry(x + y).
    .globl apx_flags_after
    .type apx_flags_after, @function
apx_flags_after:
    xor %edx, %edx
    mov %rdi, %rax
    add %rsi, %rax
    setc %dl
    add %rdx, %rax
    ret

    // CMOVcc keeps its condition read: rax = (rdi < rsi) ? rcx : rdx.
    .globl apx_cmov
    .type apx_cmov, @function
apx_cmov:
    cmp %rsi, %rdi
    mov %rdx, %rax
    cmovb %rcx, %rax
    ret

    .globl apx_imul
    .type apx_imul, @function
apx_imul:
    mov %rdi, %rax
    imul %rsi, %rax
    ret

    // Immediate source folds too.
    .globl apx_imm
    .type apx_imm, @function
apx_imm:
    mov %rdi, %rax
    add $100, %rax
    ret

    // Unary NDD forms.
    .globl apx_neg64
    .type apx_neg64, @function
apx_neg64:
    mov %rdi, %rax
    neg %rax
    ret

    .globl apx_not64
    .type apx_not64, @function
apx_not64:
    mov %rdi, %rax
    not %rax
    ret

    // The rewritten INC must preserve the CF the first add produced.
    .globl apx_inc64
    .type apx_inc64, @function
apx_inc64:
    xor %edx, %edx
    add %rsi, %rdi
    mov %rdi, %rax
    inc %rax
    setc %dl
    add %rdx, %rax
    ret

    // The rewritten immediate shift must still produce CF (NF=0).
    .globl apx_shl_imm
    .type apx_shl_imm, @function
apx_shl_imm:
    xor %edx, %edx
    mov %rdi, %rax
    shl $5, %rax
    setc %dl
    add %rdx, %rax
    ret

    .globl apx_rol_imm
    .type apx_rol_imm, @function
apx_rol_imm:
    mov %rdi, %rax
    rol $13, %rax
    ret

    // Shift by CL: the count arrives in the fourth argument register, so no
    // count-staging MOV exists for the always-on SHLX pass to claim; only
    // the APX pass can fold the value copy.
    .globl apx_shr_cl
    .type apx_shr_cl, @function
apx_shr_cl:
    mov %rdi, %rax
    shr %cl, %rax
    ret

    // Load-copy folds: the memory source moves into the NDD r/m slot.
    .globl apx_load_add
    .type apx_load_add, @function
apx_load_add:
    mov (%rdi), %rax
    add %rsi, %rax
    ret

    // A non-commutative op folds only with the loaded value kept first.
    .globl apx_load_sub_imm
    .type apx_load_sub_imm, @function
apx_load_sub_imm:
    mov (%rdi), %rax
    sub $100, %rax
    ret

    .globl apx_load_neg
    .type apx_load_neg, @function
apx_load_neg:
    mov (%rdi), %rax
    neg %rax
    ret

    .globl apx_load_shl
    .type apx_load_shl, @function
apx_load_shl:
    mov (%rdi), %rax
    shl $5, %rax
    ret

    // The condition inverts when the load folds into a CMOV:
    // rax = (rsi < rdx) ? rcx : (%rdi).
    .globl apx_load_cmov
    .type apx_load_cmov, @function
apx_load_cmov:
    cmp %rdx, %rsi
    mov (%rdi), %rax
    cmovb %rcx, %rax
    ret

    // The load address may read the destination: both forms compute the
    // address before the write.
    .globl apx_load_selfptr
    .type apx_load_selfptr, @function
apx_load_selfptr:
    mov %rdi, %rax
    mov (%rax), %rax
    add %rsi, %rax
    ret

    .section .note.GNU-stack,"",@progbits
