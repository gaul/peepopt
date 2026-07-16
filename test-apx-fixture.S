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

    // SETcc+MOVZX fuses into the promoted zero-upper SETcc.
    .globl apx_setzu
    .type apx_setzu, @function
apx_setzu:
    cmp %rsi, %rdi
    setb %al
    movzx %al, %eax
    ret

    .globl apx_setzu_ext
    .type apx_setzu_ext, @function
apx_setzu_ext:
    cmp %rsi, %rdi
    setnbe %r8b
    movzx %r8b, %r8d
    mov %r8d, %eax
    ret

    // Switch dispatch through an int32-relative .rodata jump table (the
    // clang/gcc PIC lowering). Case 1's entry point is the second
    // instruction of case 0's otherwise-fusable MOV+ADD pair: the
    // branch-target verifier must refuse that fusion or entering at case 1
    // would land inside the EVEX encoding. Case 2's pair has no interior
    // entry point and must still fuse.
    .globl apx_switch
    .type apx_switch, @function
apx_switch:
    and $3, %edi
    lea .Lapx_switch_table(%rip), %r8
    movslq (%r8,%rdi,4), %r9
    add %r8, %r9
    mov %rdx, %rax              // defines rax for the case-1 entry
    jmp *%r9
.Lapx_switch_case0:
    mov %rsi, %rax              // pair start: fusion refused (case 1 below)
.Lapx_switch_case1:
    add %rdx, %rax              // case 1 enters here mid-pair
    ret
.Lapx_switch_case2:
    mov %rsi, %rax              // no interior entry point: fuses
    sub %rdx, %rax
    ret

    .section .rodata
    .align 4
.Lapx_switch_table:
    .long .Lapx_switch_case0 - .Lapx_switch_table
    .long .Lapx_switch_case1 - .Lapx_switch_table
    .long .Lapx_switch_case2 - .Lapx_switch_table
    .long .Lapx_switch_case0 - .Lapx_switch_table
    .text

    // Exception landing pad entering mid-pair: the hand-built LSDA below
    // says the unwinder may transfer control to .Lapx_lsda_pad, the second
    // instruction of an otherwise-fusable MOV+ADD pair. The branch-target
    // verifier must parse .eh_frame/.gcc_except_table and refuse the fusion
    // (test-apx.sh asserts the pair survives via objdump).
    .globl apx_lsda
    .type apx_lsda, @function
apx_lsda:
    .cfi_startproc
    .cfi_lsda 0x1b, .Lapx_lsda_lsda    // pcrel|sdata4 LSDA pointer
    mov %rsi, %rax                     // pair start: fusion refused
.Lapx_lsda_pad:
    add %rdx, %rax                     // landing pad enters here mid-pair
    ret
    .cfi_endproc

    .section .gcc_except_table,"a",@progbits
    .align 4
.Lapx_lsda_lsda:
    .byte 0xFF                                  // @LPStart: omit (= function start)
    .byte 0xFF                                  // @TType: omit
    .byte 0x01                                  // call-site encoding: uleb128
    .uleb128 .Lapx_lsda_cs_end - .Lapx_lsda_cs  // call-site table length
.Lapx_lsda_cs:
    .uleb128 0                                  // region start (function-relative)
    .uleb128 .Lapx_lsda_pad - apx_lsda          // region length
    .uleb128 .Lapx_lsda_pad - apx_lsda          // landing pad offset
    .uleb128 0                                  // action: cleanup
.Lapx_lsda_cs_end:
    .text

    // A symbol on the second instruction of a fusable pair (a hand-written
    // assembly pattern): anything may reference apx_symbol_mid, so the
    // branch-target verifier must treat the symbol value as a target and
    // refuse the fusion (test-apx.sh asserts the pair survives).
    .globl apx_symbol
    .type apx_symbol, @function
apx_symbol:
    mov %rsi, %rax                     // pair start: fusion refused
    .globl apx_symbol_mid
apx_symbol_mid:
    add %rdx, %rax                     // symbol lands here mid-pair
    ret

    .section .note.GNU-stack,"",@progbits
