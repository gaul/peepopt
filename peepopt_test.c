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

    /* ------ RIP-relative MOV2 must NOT be absorbed (displacement would drift) ------ */
    // MOV2 is `mov 0x100(%rip),%eax` (7 bytes). Absorption would place SHLX at
    // MOV2's offset; SHLX's different length makes the RIP-relative target
    // land on a different byte. Fall back to MOV1+shift rewrite only.
    {
        uint8_t bytes[] = {
            0x8B, 0x05, 0x00, 0x01, 0x00, 0x00,  // mov 0x100(%rip),%eax
            0x44, 0x89, 0xC1,                    // movl %r8d,%ecx
            0xD3, 0xE0,                          // sall %cl,%eax
            0xC3,                                // ret
        };
        uint8_t expect[] = {
            0x8B, 0x05, 0x00, 0x01, 0x00, 0x00,  // MOV2 preserved
            0xC4, 0xE2, 0x39, 0xF7, 0xC0,        // shlxl %r8d,%eax,%eax (MOV1+SHL only)
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

    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
