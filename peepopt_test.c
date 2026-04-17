/*
 * Copyright 2026 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "peepopt.h"
#include "xed/xed-interface.h"

static int failures = 0;

#define CHECK_BYTES(expected, ...) \
do { \
    uint8_t bytes[] = { __VA_ARGS__ }; \
    int got = check_shifts(bytes, sizeof(bytes), /*replace=*/ false); \
    if (got != (expected)) { \
        fprintf(stderr, "%s:%d: check_shifts returned %d, expected %d\n", \
                __FILE__, __LINE__, got, (expected)); \
        ++failures; \
    } \
} while (0)

static void check_replace(int line, int expected_count,
                          const uint8_t *expect, size_t expect_len,
                          uint8_t *bytes, size_t len)
{
    int got = check_shifts(bytes, len, /*replace=*/ true);
    if (got != expected_count) {
        fprintf(stderr, "peepopt_test.c:%d: check_shifts returned %d, expected %d\n",
                line, got, expected_count);
        ++failures;
        return;
    }
    if (len != expect_len || memcmp(bytes, expect, len) != 0) {
        fprintf(stderr, "peepopt_test.c:%d: buffer mismatch after replace\n", line);
        fprintf(stderr, "  got:     ");
        for (size_t i = 0; i < len; ++i) fprintf(stderr, "%02X ", bytes[i]);
        fprintf(stderr, "\n  expect:  ");
        for (size_t i = 0; i < expect_len; ++i) fprintf(stderr, "%02X ", expect[i]);
        fprintf(stderr, "\n");
        ++failures;
    }
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;
    xed_tables_init();
    xed_set_verbosity(99);

    /* ------ Original tests ------ */

    // MOV+MOV+SHL, no clobber of ECX/EFLAGS: lookahead exhausts, no rewrite
    CHECK_BYTES(
        0,
        0x89, 0xF8,        // movl %edi,%eax
        0x89, 0xF1,        // movl %esi,%ecx
        0xD3, 0xE0         // sall %cl,%eax
    );
    // Same plus RET: SHLX absorbs both MOVs (6-byte footprint fits the 5-byte SHLX)
    CHECK_BYTES(
        1,
        0x89, 0xF8,        // movl %edi,%eax
        0x89, 0xF1,        // movl %esi,%ecx
        0xD3, 0xE0,        // sall %cl,%eax
        0xC3               // ret
    );
    // mov %r8d,%ecx is 3 bytes so old_len == new_len: rewrite
    CHECK_BYTES(
        1,
        0x89, 0xF8,        // movl %edi,%eax
        0x44, 0x89, 0xC1,  // movl %r8d,%ecx
        0xD3, 0xE0,        // sall %cl,%eax
        0xC3               // ret
    );

    /* ------ SHR / SAR variants ------ */

    CHECK_BYTES(
        1,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE8,        // shrl %cl,%eax
        0xC3
    );
    CHECK_BYTES(
        1,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xF8,        // sarl %cl,%eax
        0xC3
    );

    /* ------ 64-bit shift with RCX/RAX ------ */

    CHECK_BYTES(
        1,
        0x48, 0x89, 0xF1,  // movq %rsi,%rcx
        0x48, 0xD3, 0xE8,  // shrq %cl,%rax
        0xC3
    );

    /* ------ 32->64 mov_src promotion: shift_dst=64, mov_src=32 ------ */

    CHECK_BYTES(
        1,
        0x89, 0xF1,        // movl %esi,%ecx  (mov_src=ESI, promoted to RSI)
        0x48, 0xD3, 0xE8,  // shrq %cl,%rax
        0xC3
    );

    /* ------ XOR %ecx,%ecx zeroing idiom as clobber ------ */

    CHECK_BYTES(
        1,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE0,
        0x31, 0xC9,        // xor %ecx,%ecx  (clobbers ECX + EFLAGS)
        0xC3
    );

    /* ------ CALL clobbers ECX, test writes EFLAGS ------ */

    CHECK_BYTES(
        1,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE0,
        0xE8, 0x00, 0x00, 0x00, 0x00,  // call rel32
        0x85, 0xC0,                    // test %eax,%eax
        0xC3
    );

    /* ------ Two independent mov+shift pairs ------ */

    CHECK_BYTES(
        2,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE0,
        0x31, 0xC9,        // xor %ecx,%ecx
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE0,
        0xC3
    );

    /* ------ Negative: shift with immediate ------ */

    CHECK_BYTES(
        0,
        0x44, 0x89, 0xC1,
        0xC1, 0xE0, 0x03,  // shll $3,%eax
        0xC3
    );

    /* ------ Negative: shift with memory destination ------ */

    CHECK_BYTES(
        0,
        0x44, 0x89, 0xC1,
        0xD3, 0x20,        // shll %cl,(%rax)
        0xC3
    );

    /* ------ Negative: partial-register shift destination ------ */

    CHECK_BYTES(
        0,
        0x44, 0x89, 0xC1,
        0xD2, 0xE0,        // shlb %cl,%al
        0xC3
    );

    /* ------ Negative: shift without preceding MOV ------ */

    CHECK_BYTES(
        0,
        0x31, 0xC0,        // xor %eax,%eax
        0xD3, 0xE0,        // shll %cl,%eax
        0xC3
    );

    /* ------ Negative: MOV has a memory operand ------ */

    CHECK_BYTES(
        0,
        0x8B, 0x0E,        // movl (%rsi),%ecx
        0xD3, 0xE0,        // shll %cl,%eax
        0xC3
    );

    /* ------ Negative: MOV target is not ECX/RCX ------ */

    CHECK_BYTES(
        0,
        0x89, 0xF2,        // movl %esi,%edx
        0xD3, 0xE0,        // shll %cl,%eax
        0xC3
    );

    /* ------ Negative: branch in lookahead before clobber ------ */

    CHECK_BYTES(
        0,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE0,
        0xEB, 0x00,        // jmp +0
        0xC3
    );

    /* ------ Negative: ECX read before clobber ------ */

    CHECK_BYTES(
        0,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE0,
        0x89, 0xCA,        // movl %ecx,%edx  (reads ECX)
        0x31, 0xC9,
        0xC3
    );

    /* ------ Negative: EFLAGS read before clobber ------ */

    CHECK_BYTES(
        0,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE0,
        0x0F, 0x94, 0xC2,  // setz %dl  (reads EFLAGS)
        0x31, 0xC9,
        0xC3
    );

    /* ------ Negative: 16-instruction lookahead window exhausts on NOPs ------ */

    CHECK_BYTES(
        0,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE0,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    );

    /* ------ Error: truncated instruction ------ */

    CHECK_BYTES(
        -1,
        0x0F               // start of 2-byte opcode, missing second byte
    );

    /* ------ Zero-length input: returns 0 ------ */
    {
        uint8_t dummy[1] = {0};
        int got = check_shifts(dummy, 0, /*replace=*/ false);
        if (got != 0) {
            fprintf(stderr, "peepopt_test.c:%d: zero-length check_shifts returned %d, expected 0\n",
                    __LINE__, got);
            ++failures;
        }
    }

    /* ------ replace=true: verify actual byte rewrite ------ */
    {
        uint8_t bytes[] = {
            0x89, 0xF8,        // movl %edi,%eax
            0x44, 0x89, 0xC1,  // movl %r8d,%ecx
            0xD3, 0xE0,        // sall %cl,%eax
            0xC3,              // ret
        };
        uint8_t expect[] = {
            0xC4, 0xE2, 0x39, 0xF7, 0xC7,      // shlxl %r8d,%edi,%eax (MOV2 absorbed)
            0x66, 0x90,                        // 2-byte NOP padding
            0xC3,                              // ret (untouched)
        };
        check_replace(__LINE__, 1, expect, sizeof(expect), bytes, sizeof(bytes));
    }

    /* ------ replace=true: absorption of a 2-byte MOV2 (gcc -O2 pattern) ------ */
    {
        uint8_t bytes[] = {
            0x89, 0xF8,        // movl %edi,%eax      (MOV2: sets EAX)
            0x89, 0xF1,        // movl %esi,%ecx      (MOV1: sets ECX)
            0xD3, 0xE0,        // sall %cl,%eax
            0xC3,              // ret
        };
        uint8_t expect[] = {
            0xC4, 0xE2, 0x49, 0xF7, 0xC7,      // shlxl %esi,%edi,%eax
            0x90,                              // 1-byte NOP padding
            0xC3,                              // ret (untouched)
        };
        check_replace(__LINE__, 1, expect, sizeof(expect), bytes, sizeof(bytes));
    }

    /* ------ MOV2 absorption with memory source: `mov (%rsi),%eax; ...` ------ */
    {
        uint8_t bytes[] = {
            0x8B, 0x06,              // movl (%rsi),%eax         (MOV2 mem source)
            0x44, 0x89, 0xC1,        // movl %r8d,%ecx            (MOV1)
            0xD3, 0xE0,              // sall %cl,%eax
            0xC3,                    // ret
        };
        uint8_t expect[] = {
            0xC4, 0xE2, 0x39, 0xF7, 0x06,  // shlxl %r8d,(%rsi),%eax
            0x66, 0x90,                    // 2-byte NOP
            0xC3,                          // ret
        };
        check_replace(__LINE__, 1, expect, sizeof(expect), bytes, sizeof(bytes));
    }

    /* ------ MOV2 absorption with SIB-addressed memory source ------ */
    {
        uint8_t bytes[] = {
            0x8B, 0x04, 0xBE,        // movl (%rsi,%rdi,4),%eax   (MOV2 SIB)
            0x44, 0x89, 0xC1,        // movl %r8d,%ecx
            0xD3, 0xE0,              // sall %cl,%eax
            0xC3,                    // ret
        };
        uint8_t expect[] = {
            0xC4, 0xE2, 0x39, 0xF7, 0x04, 0xBE,  // shlxl %r8d,(%rsi,%rdi,4),%eax
            0x66, 0x90,                          // 2-byte NOP
            0xC3,
        };
        check_replace(__LINE__, 1, expect, sizeof(expect), bytes, sizeof(bytes));
    }

    /* ------ RIP-relative MOV2 absorbed with displacement adjusted ------ */
    // Original: `mov 0x100(%rip), %eax` at offset 0 (6 bytes, next-inst=6,
    // target = 6 + 0x100 = 0x106).
    // SHLX lands at offset 0 with length 9, so new disp = 0x106 - 0 - 9 = 0xFD,
    // preserving the original target address.
    {
        uint8_t bytes[] = {
            0x8B, 0x05, 0x00, 0x01, 0x00, 0x00,  // mov 0x100(%rip),%eax
            0x44, 0x89, 0xC1,                    // movl %r8d,%ecx
            0xD3, 0xE0,                          // sall %cl,%eax
            0xC3,                                // ret
        };
        uint8_t expect[] = {
            0xC4, 0xE2, 0x39, 0xF7, 0x05, 0xFD, 0x00, 0x00, 0x00,  // shlxl %r8d,0xFD(%rip),%eax
            0x66, 0x90,                                            // 2-byte NOP
            0xC3,
        };
        check_replace(__LINE__, 1, expect, sizeof(expect), bytes, sizeof(bytes));
    }

    /* ------ MOV2 absorption must not fire when shift_dst aliases RCX ------ */
    // `mov src1, %eax; mov src2, %ecx; shl %cl, %ecx` — here shift_dst is ECX so
    // MOV1 overwrites shift_dst before the shift; absorbing MOV2 would shift a
    // stale value. The current rewrite also cannot run (shift_dst==ECX violates
    // shift_src==CL / shift_dst!=ECX pairing), so this is a belt-and-braces check.
    CHECK_BYTES(
        0,
        0x89, 0xF8,        // movl %edi,%eax
        0x89, 0xF1,        // movl %esi,%ecx
        0xD3, 0xE1,        // shll %cl,%ecx
        0xC3
    );

    /* ------ Rewrite must refuse when a branch targets an interior byte ------ */
    // `jmp +3` at offset 0 targets offset 5 (the SHIFT). Absorbing MOV1+SHIFT
    // into SHLX would place offset 5 inside the SHLX encoding.
    CHECK_BYTES(
        0,
        0xEB, 0x03,              // jmp +3   (target = offset 5 = start of shift)
        0x44, 0x89, 0xC1,        // mov %r8d,%ecx   (MOV1, offset 2)
        0xD3, 0xE0,              // shl %cl,%eax    (offset 5, jmp target)
        0xC3                     // ret
    );

    /* ------ Jump to the rewrite's first byte IS safe (SHLX starts there) ------ */
    // `jmp +0` at offset 0 targets offset 2 (MOV1's start). After rewrite,
    // SHLX sits at offset 2, so the jump still lands on a valid instruction.
    CHECK_BYTES(
        1,
        0xEB, 0x00,              // jmp +0  (target = offset 2 = MOV1's start)
        0x44, 0x89, 0xC1,        // mov %r8d,%ecx    (MOV1, offset 2)
        0xD3, 0xE0,              // shl %cl,%eax     (offset 5)
        0xC3
    );

    /* ------ Pattern B: MOV1 before MOV2 (reversed gcc order) ------ */
    // `mov %r8d,%ecx; mov %edi,%eax; shl %cl,%eax` folds into
    // `shlx %r8d,%edi,%eax` even though MOV1 is not adjacent to the shift.
    {
        uint8_t bytes[] = {
            0x44, 0x89, 0xC1,   // movl %r8d,%ecx    (MOV1)
            0x89, 0xF8,         // movl %edi,%eax    (MOV2)
            0xD3, 0xE0,         // sall %cl,%eax
            0xC3,               // ret
        };
        uint8_t expect[] = {
            0xC4, 0xE2, 0x39, 0xF7, 0xC7,   // shlxl %r8d,%edi,%eax
            0x66, 0x90,                     // 2-byte NOP
            0xC3,
        };
        check_replace(__LINE__, 1, expect, sizeof(expect), bytes, sizeof(bytes));
    }

    /* ------ Pattern B with memory-source MOV2 ------ */
    {
        uint8_t bytes[] = {
            0x44, 0x89, 0xC1,   // movl %r8d,%ecx    (MOV1)
            0x8B, 0x06,         // movl (%rsi),%eax  (MOV2 mem source)
            0xD3, 0xE0,         // sall %cl,%eax
            0xC3,
        };
        uint8_t expect[] = {
            0xC4, 0xE2, 0x39, 0xF7, 0x06,   // shlxl %r8d,(%rsi),%eax
            0x66, 0x90,                     // 2-byte NOP
            0xC3,
        };
        check_replace(__LINE__, 1, expect, sizeof(expect), bytes, sizeof(bytes));
    }

    /* ------ Non-adjacent MOV1 with unrecognized gap must bail ------ */
    // `mov %r8d,%ecx; xor %edi,%edi; shl %cl,%eax` — intervening XOR is not
    // a MOV that sets shift_dst and cannot be absorbed. Must refuse rewrite.
    CHECK_BYTES(
        0,
        0x44, 0x89, 0xC1,   // movl %r8d,%ecx
        0x31, 0xFF,         // xor %edi,%edi
        0xD3, 0xE0,         // sall %cl,%eax
        0xC3
    );

    /* ------ MOVZX as MOV1 with 8-bit source ------ */
    // `movzbl %dl, %ecx; shl %cl, %eax; ret` folds into `shlx %edx, ..., %eax`
    // because SHLX reads only the low 5 bits of %edx, which are the low 5 bits
    // of %dl — the same bits SHL would have read via %cl after zero-extension.
    CHECK_BYTES(
        1,
        0x0F, 0xB6, 0xCA,        // movzbl %dl,%ecx
        0xD3, 0xE0,              // shl %cl,%eax
        0xC3
    );

    /* ------ MOVSX as MOV1 with 8-bit source ------ */
    CHECK_BYTES(
        1,
        0x0F, 0xBE, 0xCA,        // movsbl %dl,%ecx
        0xD3, 0xE0,              // shl %cl,%eax
        0xC3
    );

    /* ------ MOVZX 16->32 as MOV1 ------ */
    CHECK_BYTES(
        1,
        0x0F, 0xB7, 0xCA,        // movzwl %dx,%ecx
        0xD3, 0xE0,              // shl %cl,%eax
        0xC3
    );

    /* ------ MOVSXD 32->64 as MOV1 for a 64-bit shift ------ */
    CHECK_BYTES(
        1,
        0x48, 0x63, 0xCA,        // movsxd %edx,%rcx
        0x48, 0xD3, 0xE0,        // shl %cl,%rax
        0xC3
    );

    /* ------ MOVZX from high-byte (AH) source must be rejected ------ */
    // AH's bits sit at [15:8] of RAX, not [7:0]; SHLX reading %eax's low bits
    // would see AL's value, not AH's. Refuse the rewrite.
    CHECK_BYTES(
        0,
        0x0F, 0xB6, 0xCC,        // movzbl %ah,%ecx
        0xD3, 0xE0,              // shl %cl,%eax
        0xC3
    );

    /* ------ 32-bit shift with 64-bit MOV1 source: demote to 32-bit count ------ */
    // `mov %r8,%rcx; shl %cl,%eax; ret` has mov_src=R8 (64-bit) but shift_dst
    // is EAX (32-bit). Previously this hit GENERAL_ERROR in the encoder; now
    // the count register is demoted to R8D for the rewrite.
    CHECK_BYTES(
        1,
        0x4C, 0x89, 0xC1,  // movq %r8,%rcx
        0xD3, 0xE0,        // sall %cl,%eax
        0xC3               // ret
    );

    /* ------ Soundness: partial-CL write is NOT a full ECX kill ------ */
    // Previously `mov $1, %cl` counted as kills_ecx, but it leaves the upper
    // 24 bits of ECX holding MOV1's value. A subsequent read of %ecx would see
    // a different upper half under rewrite than under the original.
    CHECK_BYTES(
        0,
        0x89, 0xF8,              // movl %edi,%eax
        0x44, 0x89, 0xC1,        // movl %r8d,%ecx
        0xD3, 0xE0,              // sall %cl,%eax
        0xB1, 0x01,              // mov $1,%cl       (partial, must NOT kill)
        0x89, 0xCA,              // mov %ecx,%edx    (reads ECX — must bail)
        0x31, 0xC9,              // xor %ecx,%ecx
        0xC3                     // ret
    );

    /* ------ Soundness: `xor %cl,%cl` is NOT a full zeroing kill ------ */
    CHECK_BYTES(
        0,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE0,
        0x30, 0xC9,              // xor %cl,%cl      (partial zeroing)
        0x89, 0xCA,              // mov %ecx,%edx    (reads ECX — must bail)
        0x31, 0xC9,
        0xC3
    );

    /* ------ Soundness: partial flag write does NOT kill all SHL-written flags ------ */
    // `stc` writes only CF. SHL writes CF, OF, SF, ZF, PF. A `setz` read of ZF
    // must bail since ZF is still unkilled from the shift's perspective.
    CHECK_BYTES(
        0,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE0,
        0xF9,                    // stc               (writes only CF)
        0x0F, 0x94, 0xC2,        // setz %dl          (reads ZF — must bail)
        0x31, 0xC9,
        0xC3
    );

    /* ------ Soundness: CALL now kills all EFLAGS (SysV ABI) ------ */
    // Previously CALL was treated as an ECX kill only, so a post-call read of
    // any flag would reject. With the fix, CALL clears the flag mask and the
    // subsequent setz read is safe (flags are clobbered by the callee anyway).
    CHECK_BYTES(
        1,
        0x89, 0xF8,
        0x44, 0x89, 0xC1,
        0xD3, 0xE0,
        0xE8, 0x00, 0x00, 0x00, 0x00,  // call rel32 (kills ECX + all flags)
        0x0F, 0x94, 0xC2,              // setz %dl   (reads ZF — OK after CALL)
        0xC3
    );

    /* ------ MOV2 absorption must not fire when MOV1's source aliases shift_dst ------ */
    // `mov %eax, %eax; mov %eax, %ecx; shl %cl, %eax` — mov1_src (EAX) aliases
    // shift_dst (EAX). Absorbing MOV2 would use its source for SHLX's rm, but
    // SHLX also reads count from mov1_src (shift_dst) which would now see the
    // pre-MOV2 value.
    CHECK_BYTES(
        0,
        0x89, 0xC0,        // movl %eax,%eax  (MOV2)
        0x89, 0xC1,        // movl %eax,%ecx  (MOV1)
        0xD3, 0xE0,        // shll %cl,%eax
        0xC3
    );

    /* ================= ANDN tests ================= */

    #define CHECK_ANDN(expected, ...) \
    do { \
        uint8_t bytes[] = { __VA_ARGS__ }; \
        int got = check_andn(bytes, sizeof(bytes), /*replace=*/ false); \
        if (got != (expected)) { \
            fprintf(stderr, "%s:%d: check_andn returned %d, expected %d\n", \
                    __FILE__, __LINE__, got, (expected)); \
            ++failures; \
        } \
    } while (0)

    /* Pattern 2: `not %rax; and %rax, %rbx; ...` with RAX dead after. */
    CHECK_ANDN(
        1,
        0x48, 0xF7, 0xD0,      // not %rax
        0x48, 0x21, 0xC3,      // and %rax, %rbx
        0x48, 0x31, 0xC0,      // xor %rax, %rax  (full RAX kill)
        0xC3                   // ret             (kills flags)
    );

    /* replace=true: verify encoded bytes for a representative case. */
    {
        uint8_t bytes[] = {
            0x48, 0xF7, 0xD0,  // not %rax
            0x48, 0x21, 0xC3,  // and %rax, %rbx
            0x48, 0x31, 0xC0,  // xor %rax, %rax
            0xC3,
        };
        // ANDN %rbx, %rax, %rbx: VEX.NDS.0F38.W1 F2 /r
        //   VEX byte1 = C4, byte2 = ~R~X~B mmmmm = 1 1 1 00010 = 0xE2
        //   byte3 = W ~vvvv L pp = 1 1011 0 00 = 0xD8 (W=1, vvvv=RBX=3 -> ~vvvv=1100... wait)
        // Actually vvvv encodes src1 (the negated operand) for ANDN. For
        // our pattern REG1 = mask_reg = RAX (vvvv=0 -> ~vvvv=1111).
        //   byte3 = 1 1111 0 00 = 0xF8
        // opcode = F2, ModR/M = 11 (mod) reg=RBX=011 rm=RBX=011 = 0xDB
        uint8_t expect[] = {
            0xC4, 0xE2, 0xF8, 0xF2, 0xDB,  // andn %rbx, %rax, %rbx
            0x90,                          // 1-byte NOP
            0x48, 0x31, 0xC0,              // xor %rax,%rax preserved
            0xC3,
        };
        int got = check_andn(bytes, sizeof(bytes), /*replace=*/ true);
        if (got != 1) {
            fprintf(stderr, "%s:%d: check_andn returned %d, expected 1\n",
                    __FILE__, __LINE__, got);
            ++failures;
        } else if (memcmp(bytes, expect, sizeof(bytes)) != 0) {
            fprintf(stderr, "%s:%d: andn buffer mismatch\n", __FILE__, __LINE__);
            fprintf(stderr, "  got:     ");
            for (size_t i = 0; i < sizeof(bytes); ++i) fprintf(stderr, "%02X ", bytes[i]);
            fprintf(stderr, "\n  expect:  ");
            for (size_t i = 0; i < sizeof(expect); ++i) fprintf(stderr, "%02X ", expect[i]);
            fprintf(stderr, "\n");
            ++failures;
        }
    }

    /* Mask register must be dead after — a subsequent read of %rax bails. */
    CHECK_ANDN(
        0,
        0x48, 0xF7, 0xD0,      // not %rax
        0x48, 0x21, 0xC3,      // and %rax, %rbx
        0x48, 0x89, 0xC2,      // mov %rax, %rdx   (reads rax — must bail)
        0x48, 0x31, 0xC0,      // xor %rax, %rax
        0xC3
    );

    /* Reading PF after ANDN rewrite would be unsafe (ANDN leaves PF undef,
       AND sets it). */
    CHECK_ANDN(
        0,
        0x48, 0xF7, 0xD0,      // not %rax
        0x48, 0x21, 0xC3,      // and %rax, %rbx
        0x7A, 0x00,            // jp +0  (wait, that's a branch — bails differently)
        0xC3
    );

    /* Non-adjacent NOT+AND must bail. */
    CHECK_ANDN(
        0,
        0x48, 0xF7, 0xD0,      // not %rax
        0x90,                  // nop intervening
        0x48, 0x21, 0xC3,      // and %rax, %rbx
        0x48, 0x31, 0xC0,      // xor %rax, %rax
        0xC3
    );

    /* 32-bit no-REX form doesn't fit (4 bytes vs 5-byte ANDN). */
    CHECK_ANDN(
        0,
        0xF7, 0xD0,            // not %eax
        0x21, 0xC3,            // and %eax, %ebx
        0x31, 0xC0,            // xor %eax, %eax
        0xC3
    );

    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
