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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "peepopt.h"
#include "xed/xed-interface.h"

static bool g_verbose = false;

void peepopt_set_verbose(bool verbose)
{
    g_verbose = verbose;
}

#define VLOG(...) do { if (g_verbose) printf(__VA_ARGS__); } while (0)

#define HISTORY_SIZE 8

struct inst_history_entry {
    xed_decoded_inst_t xedd;
    size_t offset;
};

struct inst_history {
    struct inst_history_entry entries[HISTORY_SIZE];
    size_t count;
    size_t head;
};

static void history_reset(struct inst_history *h)
{
    h->count = 0;
    h->head = 0;
}

static void history_push(struct inst_history *h, const xed_decoded_inst_t *xedd, size_t offset)
{
    h->entries[h->head].xedd = *xedd;
    h->entries[h->head].offset = offset;
    h->head = (h->head + 1) % HISTORY_SIZE;
    if (h->count < HISTORY_SIZE) {
        h->count++;
    }
}

static const struct inst_history_entry *history_at(const struct inst_history *h, size_t dist)
{
    if (dist == 0 || dist > h->count) {
        return NULL;
    }
    size_t idx = (h->head + HISTORY_SIZE - dist) % HISTORY_SIZE;
    return &h->entries[idx];
}

static bool reg_aliases_rcx(xed_reg_enum_t reg)
{
    return reg == XED_REG_RCX || reg == XED_REG_ECX || reg == XED_REG_CX ||
           reg == XED_REG_CL  || reg == XED_REG_CH;
}

static bool action_reads(xed_operand_action_enum_t a)
{
    return a == XED_OPERAND_ACTION_R   || a == XED_OPERAND_ACTION_CR  ||
           a == XED_OPERAND_ACTION_RW  || a == XED_OPERAND_ACTION_RCW ||
           a == XED_OPERAND_ACTION_CRW;
}

static bool action_writes(xed_operand_action_enum_t a)
{
    return a == XED_OPERAND_ACTION_W   || a == XED_OPERAND_ACTION_CW  ||
           a == XED_OPERAND_ACTION_RW  || a == XED_OPERAND_ACTION_RCW ||
           a == XED_OPERAND_ACTION_CRW;
}

static void inst_touches_rcx(const xed_decoded_inst_t *xedd, bool *writes, bool *reads)
{
    *writes = false;
    *reads = false;
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned int n = xed_inst_noperands(xi);
    for (unsigned int i = 0; i < n; i++) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_reg_enum_t reg = xed_decoded_inst_get_reg(xedd, xed_operand_name(op));
        if (!reg_aliases_rcx(reg)) {
            continue;
        }
        xed_operand_action_enum_t a = xed_operand_rw(op);
        if (action_writes(a)) *writes = true;
        if (action_reads(a))  *reads = true;
    }
    // Base/index registers of a memory operand are read to compute the
    // effective address, but XED does not surface that read through
    // xed_operand_rw on the operand list above. Without folding them in, an
    // addressing use of RCX (e.g. `mov (%rcx),%edx` or `mov (,%rcx,4),%edx`)
    // looks dead, and the rewrite would delete the MOV that defined RCX,
    // leaving the load/store pointing at a stale value.
    unsigned int nmem = xed_decoded_inst_number_of_memory_operands(xedd);
    for (unsigned int m = 0; m < nmem; m++) {
        if (reg_aliases_rcx(xed_decoded_inst_get_base_reg(xedd, m)) ||
            reg_aliases_rcx(xed_decoded_inst_get_index_reg(xedd, m))) {
            *reads = true;
        }
    }
}

// Scan history backward (most-recent first) for the nearest instruction that writes RCX/ECX.
// Returns NULL if an intervening instruction reads RCX without writing it (which would break
// the def-use chain from the writer to the shift's CL read), or if no writer is in the window.
static const struct inst_history_entry *history_find_rcx_def(const struct inst_history *h)
{
    for (size_t dist = 1; dist <= h->count; dist++) {
        const struct inst_history_entry *e = history_at(h, dist);
        bool w = false, r = false;
        inst_touches_rcx(&e->xedd, &w, &r);
        if (w) {
            return e;
        }
        if (r) {
            return NULL;
        }
    }
    return NULL;
}

static bool is_basic_block_terminator(const xed_decoded_inst_t *xedd)
{
    xed_category_enum_t c = xed_decoded_inst_get_category(xedd);
    return c == XED_CATEGORY_COND_BR || c == XED_CATEGORY_UNCOND_BR ||
           c == XED_CATEGORY_CALL    || c == XED_CATEGORY_RET;
}

// Forward lookahead bails on conditional or unconditional branches only; CALL
// and RET are handled as ECX/EFLAGS kills via the ABI (caller-saved regs).
static bool is_branch_bailout(const xed_decoded_inst_t *xedd)
{
    xed_category_enum_t c = xed_decoded_inst_get_category(xedd);
    return c == XED_CATEGORY_COND_BR || c == XED_CATEGORY_UNCOND_BR;
}

// Full-width ECX or RCX. Sub-registers (CL/CH/CX) only overwrite part of the
// register and can't be treated as a kill of MOV1's contribution.
static bool reg_is_full_ecx(xed_reg_enum_t reg)
{
    return reg == XED_REG_ECX || reg == XED_REG_RCX;
}

// `xor reg, reg` produces 0 regardless of the prior value of reg, so for
// dataflow purposes it's a pure write even though XED reports operand 0 as RW.
// Only full-width ECX/RCX zeroing counts; `xor %cl, %cl` leaves the upper bits
// of ECX untouched and does not kill MOV1's value.
static bool is_zeroing_idiom_on_rcx(const xed_decoded_inst_t *xedd)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_XOR) {
        return false;
    }
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    if (xed_inst_noperands(xi) < 2) {
        return false;
    }
    const xed_operand_t *op0 = xed_inst_operand(xi, 0);
    const xed_operand_t *op1 = xed_inst_operand(xi, 1);
    xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, xed_operand_name(op0));
    xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, xed_operand_name(op1));
    return r0 == r1 && reg_is_full_ecx(r0);
}

static bool kills_ecx(const xed_decoded_inst_t *xedd)
{
    xed_category_enum_t c = xed_decoded_inst_get_category(xedd);
    // ABI: caller-saved on SysV / clobbered across syscalls and on return.
    if (c == XED_CATEGORY_CALL || c == XED_CATEGORY_RET) {
        return true;
    }
    if (is_zeroing_idiom_on_rcx(xedd)) {
        return true;
    }
    // A pure write to the full ECX or RCX (not a sub-register). Partial writes
    // like `mov $1, %cl` or `mov ..., %cx` leave the upper bits observable.
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned int n = xed_inst_noperands(xi);
    bool full_write = false;
    bool any_read = false;
    for (unsigned int i = 0; i < n; i++) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_reg_enum_t reg = xed_decoded_inst_get_reg(xedd, xed_operand_name(op));
        if (!reg_aliases_rcx(reg)) {
            continue;
        }
        xed_operand_action_enum_t a = xed_operand_rw(op);
        if (action_reads(a)) {
            any_read = true;
        }
        if (action_writes(a) && reg_is_full_ecx(reg)) {
            full_write = true;
        }
    }
    return full_write && !any_read;
}

static bool reads_ecx(const xed_decoded_inst_t *xedd)
{
    if (is_zeroing_idiom_on_rcx(xedd)) {
        return false;
    }
    bool w = false, r = false;
    inst_touches_rcx(xedd, &w, &r);
    return r;
}

// Mask of rflags bits this instruction definitely clobbers (written or
// undefined). CALL and RET clobber everything via ABI: after RET we're in the
// caller, and a CALL may return with any rflag (SysV leaves flags
// caller-responsibility).
static uint32_t written_rflags_mask(const xed_decoded_inst_t *xedd)
{
    xed_category_enum_t c = xed_decoded_inst_get_category(xedd);
    if (c == XED_CATEGORY_CALL || c == XED_CATEGORY_RET) {
        return UINT32_MAX;
    }
    const xed_simple_flag_t *sflag = xed_decoded_inst_get_rflags_info(xedd);
    if (sflag == NULL) {
        return 0;
    }
    return xed_flag_set_mask(xed_simple_flag_get_written_flag_set(sflag)) |
           xed_flag_set_mask(xed_simple_flag_get_undefined_flag_set(sflag));
}

static uint32_t read_rflags_mask(const xed_decoded_inst_t *xedd)
{
    const xed_simple_flag_t *sflag = xed_decoded_inst_get_rflags_info(xedd);
    if (sflag == NULL) {
        return 0;
    }
    return xed_flag_set_mask(xed_simple_flag_get_read_flag_set(sflag));
}

// Accessors for an arbitrary register's alias family. `inst_touches_reg` tells
// us whether any operand touches the 64-bit alias of `query`; `kills_reg_full`
// is the "full-width pure write" analog of kills_ecx for a caller-specified
// register (no ABI assumption — CALL/RET are not treated as kills here).
static void inst_touches_reg(const xed_decoded_inst_t *xedd, xed_reg_enum_t query,
                             bool *writes, bool *reads)
{
    *writes = false;
    *reads = false;
    xed_reg_enum_t family = xed_get_largest_enclosing_register(query);
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned int n = xed_inst_noperands(xi);
    for (unsigned int i = 0; i < n; i++) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_reg_enum_t reg = xed_decoded_inst_get_reg(xedd, xed_operand_name(op));
        if (reg == XED_REG_INVALID) {
            continue;
        }
        if (xed_get_largest_enclosing_register(reg) != family) {
            continue;
        }
        xed_operand_action_enum_t a = xed_operand_rw(op);
        if (action_writes(a)) *writes = true;
        if (action_reads(a))  *reads = true;
    }
    // Base/index registers participate in the address calculation as reads but
    // are invisible to xed_operand_rw; fold them in explicitly so an addressing
    // use of `query` is not mistaken for the register being dead.
    unsigned int nmem = xed_decoded_inst_number_of_memory_operands(xedd);
    for (unsigned int m = 0; m < nmem; m++) {
        xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, m);
        xed_reg_enum_t index = xed_decoded_inst_get_index_reg(xedd, m);
        if ((base != XED_REG_INVALID &&
             xed_get_largest_enclosing_register(base) == family) ||
            (index != XED_REG_INVALID &&
             xed_get_largest_enclosing_register(index) == family)) {
            *reads = true;
        }
    }
}

// `xor %reg, %reg` (where both operands are the same full-width register) is
// a semantic kill: the result is 0 regardless of reg's prior value, so any
// read of reg inside the instruction is irrelevant.
static bool is_zeroing_idiom_on(const xed_decoded_inst_t *xedd, xed_reg_enum_t query)
{
    if (xed_decoded_inst_get_iclass(xedd) != XED_ICLASS_XOR) {
        return false;
    }
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    if (xed_inst_noperands(xi) < 2) {
        return false;
    }
    xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd,
            xed_operand_name(xed_inst_operand(xi, 0)));
    xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd,
            xed_operand_name(xed_inst_operand(xi, 1)));
    if (r0 != r1 || xed_get_register_width_bits(r0) < 32) {
        return false;
    }
    xed_reg_enum_t family = xed_get_largest_enclosing_register(query);
    return xed_get_largest_enclosing_register(r0) == family;
}

static bool kills_reg_full(const xed_decoded_inst_t *xedd, xed_reg_enum_t query)
{
    if (is_zeroing_idiom_on(xedd, query)) {
        return true;
    }
    xed_reg_enum_t family = xed_get_largest_enclosing_register(query);
    if (family == XED_REG_INVALID) {
        return false;
    }
    const xed_inst_t *xi = xed_decoded_inst_inst(xedd);
    unsigned int n = xed_inst_noperands(xi);
    bool full_write = false;
    bool any_read = false;
    for (unsigned int i = 0; i < n; i++) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_reg_enum_t reg = xed_decoded_inst_get_reg(xedd, xed_operand_name(op));
        if (reg == XED_REG_INVALID ||
            xed_get_largest_enclosing_register(reg) != family) {
            continue;
        }
        xed_operand_action_enum_t a = xed_operand_rw(op);
        if (action_reads(a)) {
            any_read = true;
        }
        if (action_writes(a) && xed_get_register_width_bits(reg) >= 32) {
            // 32-bit writes zero-extend to the full 64-bit register, so the
            // 32- or 64-bit write is a full kill. 8/16-bit writes are not.
            full_write = true;
        }
    }
    return full_write && !any_read;
}

static int check_shifts_impl(uint8_t *inst, size_t len, bool replace,
                              const uint8_t *branch_targets);

// Scan the section for PC-relative branch targets and record each target byte
// offset in the bitmap. Used before rewriting to refuse any rewrite whose
// interior bytes (i.e., anything other than the rewrite's first byte) is a
// known jump destination.
//
// This covers direct Jcc/JMP/CALL rel. Indirect branches and jump-table
// targets in .rodata are not detected — those remain a residual risk.
static void collect_branch_targets(const uint8_t *inst, size_t len,
                                    uint8_t *targets)
{
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;
    for (size_t off = 0; off < len;) {
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);
        if (xed_decode(&xedd, inst + off, len - off) != XED_ERROR_NONE) {
            return;
        }
        xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd);
        if (xed_decoded_inst_get_branch_displacement_width(&xedd) > 0 &&
            (cat == XED_CATEGORY_COND_BR ||
             cat == XED_CATEGORY_UNCOND_BR ||
             cat == XED_CATEGORY_CALL)) {
            xed_int32_t disp = xed_decoded_inst_get_branch_displacement(&xedd);
            xed_uint_t inst_len = xed_decoded_inst_get_length(&xedd);
            int64_t target = (int64_t)off + (int64_t)inst_len + (int64_t)disp;
            if (target >= 0 && (size_t)target < len) {
                size_t t = (size_t)target;
                targets[t / 8] |= (uint8_t)(1u << (t % 8));
            }
        }
        off += xed_decoded_inst_get_length(&xedd);
    }
}

// Returns true if any byte strictly between `lo` and `hi` (exclusive-exclusive
// on the low side, exclusive on the high side means [lo+1, hi)) is marked as
// a branch target. The rewrite keeps the byte at `lo` (SHLX's first byte) so
// jumps to `lo` stay correct; any interior byte gets repurposed.
static bool target_in_interior(const uint8_t *targets, size_t lo, size_t hi)
{
    for (size_t t = lo + 1; t < hi; t++) {
        if (targets[t / 8] & (uint8_t)(1u << (t % 8))) {
            return true;
        }
    }
    return false;
}

int check_shifts(uint8_t *inst, size_t len, bool replace)
{
    size_t bitmap_bytes = len > 0 ? (len + 7) / 8 : 1;
    uint8_t *targets = calloc(bitmap_bytes, 1);
    if (targets == NULL) {
        return -1;
    }
    collect_branch_targets(inst, len, targets);
    int result = check_shifts_impl(inst, len, replace, targets);
    free(targets);
    return result;
}

static int check_shifts_impl(uint8_t *inst, size_t len, bool replace,
                              const uint8_t *branch_targets)
{
    int count = 0;
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;
    struct inst_history history;
    history_reset(&history);

    for (size_t offset = 0; offset < len;) {
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);

        xed_error_enum_t err = xed_decode(&xedd, inst + offset, len - offset);
        if (err != XED_ERROR_NONE) {
            fprintf(stderr, "Decoding error at offset: %zu: %s\n", offset, xed_error_enum_t2str(err));
            return -1;
        }

        char buffer[256];
        xed_bool_t ok = xed_format_context(
                XED_SYNTAX_ATT, &xedd, buffer, sizeof(buffer),
                offset,  // IP address (for relative branch calculation) TODO: this seems incorrect
                /*context=*/ NULL, /*symbolic_callback=*/ NULL);
        if (ok) {
            VLOG("* %s [%u bytes]\n", buffer, xed_decoded_inst_get_length(&xedd));
        }

        // TODO: check XED_IFORM_SHL_GPR32_CL instead of number of memory operands?
        // TODO: SHLX supports a memory operand for one of the sources
        if (xed_decoded_inst_number_of_memory_operands(&xedd) != 0 ||
            xed_decoded_inst_get_immediate_width_bits(&xedd) != 0) {
            goto end;
        }

        int iclass = xed_decoded_inst_get_iclass(&xedd);
        if (iclass == XED_ICLASS_SHL || iclass == XED_ICLASS_SHR || iclass == XED_ICLASS_SAR) {
            // Analyze shifts to see if it is possible to rewrite with three-operand BMI equivalent:
            // 1. previous instruction is a register-register MOV
            // 2. current instruction is a shift
            // 3. subsequent instructions overwrite ECX and EFLAGS before another instruction reads them or control flow branches
            //
            // Example:
            //     89F8           movl %edi,%eax
            //     89F1           movl %esi,%ecx
            //     D3E0           sall %cl,%eax
            //     31C9           xor %ecx,%ecx
            //
            // to:
            //     C4E249F7C7     shlx %esi,%edi,%eax
            //     31C9           xor %ecx,%ecx
            //
            // TODO: these instructions are not necessarily contiguous and a more complicated analysis could find more pairs, e.g.,
            //     mov %edi, %ecx
            //     or %r8d, %edi
            //     shr %cl, %eax
            //     xor %ecx, %ecx
            const struct inst_history_entry *mov_entry = history_find_rcx_def(&history);
            if (mov_entry == NULL) {
                goto end;
            }
            const xed_decoded_inst_t *xedd_old = &mov_entry->xedd;
            int oldiclass = xed_decoded_inst_get_iclass(xedd_old);
            // MOVZX/MOVSX write the full ECX/RCX zero- or sign-extended from a
            // narrower source. The shift reads CL (= the low byte of the source
            // in both cases), so SHLX can read directly from the source register
            // -- the upper bits of the count register don't matter because SHLX
            // masks to 5 or 6 bits, and those low bits are identical whether
            // the extension is zero or sign.
            if (oldiclass != XED_ICLASS_MOV &&
                oldiclass != XED_ICLASS_MOVZX &&
                oldiclass != XED_ICLASS_MOVSX &&
                oldiclass != XED_ICLASS_MOVSXD) {
                goto end;
            }
            // MOV1's offset vs. the shift determines the rewrite layout:
            //   adjacent: [MOV1][SHIFT]           -> SHLX consumes MOV1+SHIFT
            //   gap:      [MOV1][GAP][SHIFT]      -> only rewritable if the GAP
            //                                        is exactly one MOV that
            //                                        sets shift_dst (handled as
            //                                        MOV2 absorption below).
            size_t mov1_len_for_gap = xed_decoded_inst_get_length(xedd_old);
            bool mov1_adjacent = (mov_entry->offset + mov1_len_for_gap == offset);

            VLOG("Examining MOV + shift pair\n");

            xed_reg_enum_t shift_src = XED_REG_INVALID;
            xed_reg_enum_t shift_dst = XED_REG_INVALID;
            xed_reg_enum_t mov_src = XED_REG_INVALID;
            xed_reg_enum_t mov_dst = XED_REG_INVALID;

            // Previous MOV
            // TODO: possible to merge one other MOV due to three-operand instructions?
            const xed_inst_t* xi = xed_decoded_inst_inst(xedd_old);
            unsigned int noperands = xed_inst_noperands(xi);
            for (unsigned int i = 0; i < noperands; i++) {
                const xed_operand_t *op = xed_inst_operand(xi, i);
                xed_operand_enum_t op_name = xed_operand_name(op);
                if (!xed_operand_is_register(op_name))
                    goto end;

                xed_operand_action_enum_t action = xed_operand_rw(op);
                xed_reg_enum_t reg = xed_decoded_inst_get_reg(xedd_old, xed_operand_name(op));
                VLOG("mov   operand %u %s action register %s\n", i, xed_operand_action_enum_t2str(action), xed_reg_enum_t2str(reg));

                if (action == XED_OPERAND_ACTION_R) {
                    mov_src = reg;
                } else if (action == XED_OPERAND_ACTION_W) {
                    mov_dst = reg;
                } else {
                    goto end;
                }
            }

            // Current shift
            xi = xed_decoded_inst_inst(&xedd);
            noperands = xed_inst_noperands(xi);
            for (unsigned int i = 0; i < noperands; i++) {
                const xed_operand_t *op = xed_inst_operand(xi, i);
                xed_operand_enum_t op_name = xed_operand_name(op);
                if (!xed_operand_is_register(op_name))
                    goto end;

                xed_operand_action_enum_t action = xed_operand_rw(op);
                xed_reg_enum_t reg = xed_decoded_inst_get_reg(&xedd, xed_operand_name(op));
                VLOG("shift operand %u %s action register %s\n", i, xed_operand_action_enum_t2str(action), xed_reg_enum_t2str(reg));

                if (action == XED_OPERAND_ACTION_R) {
                    shift_src = reg;
                } else if (action == XED_OPERAND_ACTION_RW || action == XED_OPERAND_ACTION_W) {
                    if (xed_get_register_width_bits(reg) < 32) {
                        VLOG("Ignore partial registers\n");
                        goto end;
                    }
                    shift_dst = reg;
                } else if (action == XED_OPERAND_ACTION_CW) {
                    // ignore FLAGS
                } else {
                    goto end;
                }
            }

            VLOG("MOV src: %s MOV dst: %s SHR src: %s SHR dst: %s\n",
                    xed_reg_enum_t2str(mov_src), xed_reg_enum_t2str(mov_dst),
                    xed_reg_enum_t2str(shift_src), xed_reg_enum_t2str(shift_dst));
            // TODO: check that the source and dest operands and widths match
            if (!((mov_dst == XED_REG_ECX || mov_dst == XED_REG_RCX) && shift_src == XED_REG_CL)) {
                VLOG("Wrong register pairs for replacement\n");
                goto end;
            }

            // SHLX requires the count register's width to match the effective
            // operand width (32 or 64). x86 shifts mask the count to 5 or 6
            // bits, and those low bits alias across every width of a given
            // GPR, so we can substitute the 32- or 64-bit parent register.
            //
            // High-byte registers (AH/BH/CH/DH) are the exception: their bits
            // live in bits [15:8] of the parent, not [7:0], so the low 5 bits
            // of the parent aren't the low 5 bits of AH/BH/CH/DH. Refuse them.
            if (mov_src == XED_REG_AH || mov_src == XED_REG_BH ||
                mov_src == XED_REG_CH || mov_src == XED_REG_DH) {
                VLOG("MOV1 source is a high-byte register; cannot use in SHLX\n");
                goto end;
            }
            unsigned int shift_width = xed_get_register_width_bits(shift_dst);
            unsigned int mov_src_width = xed_get_register_width_bits(mov_src);
            if (mov_src_width != shift_width) {
                xed_reg_enum_t parent64 = xed_get_largest_enclosing_register(mov_src);
                if (parent64 == XED_REG_INVALID) {
                    goto end;
                }
                if (shift_width == 64) {
                    mov_src = parent64;
                } else {
                    // Demote 64 -> 32 via enum-offset arithmetic. The GPR enum
                    // is laid out so RXX - EXX is the same constant across the
                    // legacy and R8..R15 ranges.
                    mov_src = parent64 - XED_REG_RAX + XED_REG_EAX;
                }
            }

            // Optionally absorb a second MOV that supplies shift_dst's value.
            // Two layouts are supported:
            //   Pattern A (MOV1 adjacent): [MOV2][MOV1][SHIFT]
            //                              MOV2 candidate is at history distance 2.
            //   Pattern B (MOV1 non-adjacent): [MOV1][MOV2][SHIFT]
            //                              MOV2 candidate is at history distance 1
            //                              and must exactly fill the MOV1<->SHIFT gap.
            // Either folds into `shlx %count, %value, %shift_dst` (or the memory
            // form). ECX is dead after the shift per the forward lookahead, and
            // MOV1 is reg-to-reg so it can't alter memory or mov2_src.
            xed_reg_enum_t shlx_rm = shift_dst;
            size_t rewrite_offset = mov_entry->offset;
            const xed_decoded_inst_t *mov2_mem_source = NULL;
            size_t mov2_source_offset = 0;
            size_t mov2_source_len = 0;
            if (!reg_aliases_rcx(shift_dst) &&
                xed_get_largest_enclosing_register(mov_src) != xed_get_largest_enclosing_register(shift_dst)) {
                const struct inst_history_entry *mov2_entry = NULL;
                bool mov2_layout_ok = false;
                if (mov1_adjacent) {
                    mov2_entry = history_at(&history, 2);
                    if (mov2_entry != NULL) {
                        size_t mov2_end = mov2_entry->offset +
                                          xed_decoded_inst_get_length(&mov2_entry->xedd);
                        mov2_layout_ok = (mov2_end == mov_entry->offset);
                    }
                } else {
                    mov2_entry = history_at(&history, 1);
                    if (mov2_entry != NULL) {
                        size_t mov2_end = mov2_entry->offset +
                                          xed_decoded_inst_get_length(&mov2_entry->xedd);
                        mov2_layout_ok =
                                (mov2_entry->offset == mov_entry->offset + mov1_len_for_gap) &&
                                (mov2_end == offset);
                    }
                }
                if (mov2_layout_ok &&
                    xed_decoded_inst_get_iclass(&mov2_entry->xedd) == XED_ICLASS_MOV &&
                    xed_decoded_inst_get_immediate_width_bits(&mov2_entry->xedd) == 0) {
                    unsigned int nmem = xed_decoded_inst_number_of_memory_operands(&mov2_entry->xedd);
                    const xed_inst_t *xi2 = xed_decoded_inst_inst(&mov2_entry->xedd);
                    unsigned int n2 = xed_inst_noperands(xi2);
                    xed_reg_enum_t mov2_dst = XED_REG_INVALID;
                    xed_reg_enum_t mov2_src_reg = XED_REG_INVALID;
                    bool form_ok = (nmem == 0 || nmem == 1);
                    for (unsigned int i = 0; form_ok && i < n2; i++) {
                        const xed_operand_t *op = xed_inst_operand(xi2, i);
                        xed_operand_enum_t op_name = xed_operand_name(op);
                        xed_operand_action_enum_t act = xed_operand_rw(op);
                        if (xed_operand_is_register(op_name)) {
                            xed_reg_enum_t reg = xed_decoded_inst_get_reg(&mov2_entry->xedd, op_name);
                            if (act == XED_OPERAND_ACTION_W) {
                                mov2_dst = reg;
                            } else if (act == XED_OPERAND_ACTION_R) {
                                mov2_src_reg = reg;
                            } else {
                                form_ok = false;
                            }
                        } else if (op_name == XED_OPERAND_MEM0) {
                            if (act != XED_OPERAND_ACTION_R) {
                                form_ok = false;
                            }
                        } else if (op_name != XED_OPERAND_BASE0 &&
                                   op_name != XED_OPERAND_INDEX &&
                                   op_name != XED_OPERAND_SCALE &&
                                   op_name != XED_OPERAND_SEG0) {
                            form_ok = false;
                        }
                    }
                    // A memory-source MOV2 is folded into SHLX at rewrite_offset,
                    // which deletes MOV1 (the writer of RCX). If MOV2 addresses
                    // through RCX, the absorbed load would dereference the stale,
                    // pre-MOV1 value of RCX. Refuse it. (Conservative: this also
                    // rejects the rarer layout where MOV2 precedes MOV1 and the
                    // RCX value would actually be unaffected.)
                    bool mov2_mem_addr_ok =
                        nmem != 1 ||
                        (!reg_aliases_rcx(xed_decoded_inst_get_base_reg(&mov2_entry->xedd, 0)) &&
                         !reg_aliases_rcx(xed_decoded_inst_get_index_reg(&mov2_entry->xedd, 0)));
                    if (form_ok &&
                        mov2_mem_addr_ok &&
                        mov2_dst == shift_dst &&
                        (nmem == 1 ||
                         (mov2_src_reg != XED_REG_INVALID && !reg_aliases_rcx(mov2_src_reg)))) {
                        if (nmem == 1) {
                            VLOG("Absorbing MOV2 with memory source into SHLX\n");
                            mov2_mem_source = &mov2_entry->xedd;
                            mov2_source_offset = mov2_entry->offset;
                            mov2_source_len = xed_decoded_inst_get_length(&mov2_entry->xedd);
                        } else {
                            VLOG("Absorbing MOV that sets shift_dst (%s := %s)\n",
                                    xed_reg_enum_t2str(mov2_dst), xed_reg_enum_t2str(mov2_src_reg));
                            shlx_rm = mov2_src_reg;
                        }
                        // Rewrite starts at the earliest absorbed instruction.
                        if (mov2_entry->offset < rewrite_offset) {
                            rewrite_offset = mov2_entry->offset;
                        }
                    }
                }
            }

            // Non-adjacent MOV1 is only safe when the intervening gap was
            // entirely filled by an absorbable MOV2.
            if (!mov1_adjacent && shlx_rm == shift_dst && mov2_mem_source == NULL) {
                VLOG("MOV1 at offset %zu is %zu bytes before shift and gap is not an absorbable MOV2; skipping\n",
                        mov_entry->offset,
                        offset - mov_entry->offset - mov1_len_for_gap);
                goto end;
            }

            VLOG("Higher confidence\n");

            // Look ahead to verify ECX is dead and every rflag SHL writes is
            // overwritten before any instruction reads it. SHLX leaves rflags
            // unchanged, so a read of any SHL-written flag before that flag is
            // clobbered would observe different values in the rewritten code.
            bool ecx_written = false;
            uint32_t shift_flags_mask = written_rflags_mask(&xedd);
            uint32_t killed_flags_mask = 0;

            size_t new_offset = offset + xed_decoded_inst_get_length(&xedd);
            for (int i = 0; i < 16 && new_offset < len; ++i) {
                xed_decoded_inst_t xedd_new;
                xed_decoded_inst_zero(&xedd_new);
                xed_decoded_inst_set_mode(&xedd_new, mmode, stack_addr_width);
                err = xed_decode(&xedd_new, inst + new_offset, len - new_offset);
                if (err != XED_ERROR_NONE) {
                    fprintf(stderr, "Decoding error at offset: %zu: %s\n", new_offset, xed_error_enum_t2str(err));
                    return -1;
                }

                ok = xed_format_context(
                        XED_SYNTAX_ATT, &xedd_new, buffer, sizeof(buffer),
                        offset,  // IP address (for relative branch calculation) TODO: this seems incorrect
                        /*context=*/ NULL, /*symbolic_callback=*/ NULL);
                if (ok) {
                    VLOG("* %s [%u bytes]\n", buffer, xed_decoded_inst_get_length(&xedd_new));
                }

                if (is_branch_bailout(&xedd_new)) {
                    VLOG("Branch, cannot replace\n");
                    goto end;
                }
                if (!ecx_written && reads_ecx(&xedd_new)) {
                    VLOG("Reading from ECX, cannot replace\n");
                    goto end;
                }
                uint32_t read_mask = read_rflags_mask(&xedd_new);
                if ((read_mask & shift_flags_mask & ~killed_flags_mask) != 0) {
                    VLOG("Reading a shift-written EFLAGS bit, cannot replace\n");
                    goto end;
                }
                if (kills_ecx(&xedd_new)) {
                    ecx_written = true;
                }
                killed_flags_mask |= written_rflags_mask(&xedd_new);

                if (ecx_written && (shift_flags_mask & ~killed_flags_mask) == 0) {
                    break;
                }

                new_offset += xed_decoded_inst_get_length(&xedd_new);
            }

            bool eflags_written = (shift_flags_mask & ~killed_flags_mask) == 0;
            if (ecx_written && eflags_written) {
                // assemble replacement instruction
                VLOG("Highest confidence that replacement is possible\n");
                uint8_t new_bytes[XED_MAX_INSTRUCTION_BYTES];
                unsigned new_len = 0;
                xed_state_t state;
                xed_state_zero(&state);
                state.mmode = XED_MACHINE_MODE_LONG_64;
                state.stack_addr_width = XED_ADDRESS_WIDTH_64b;

                xed_iclass_enum_t new_iclass =
                        iclass == XED_ICLASS_SHL ? XED_ICLASS_SHLX :
                        iclass == XED_ICLASS_SHR ? XED_ICLASS_SHRX :
                        iclass == XED_ICLASS_SAR ? XED_ICLASS_SARX :
                                                   XED_ICLASS_INVALID;
                xed_uint_t eow = xed_get_register_width_bits(shift_dst);

                xed_encoder_operand_t op_rm;
                if (mov2_mem_source != NULL) {
                    xed_uint_t mem_width_bits =
                            xed_decoded_inst_get_memory_operand_length(mov2_mem_source, 0) * 8;
                    xed_reg_enum_t mem_base = xed_decoded_inst_get_base_reg(mov2_mem_source, 0);
                    int64_t disp = xed_decoded_inst_get_memory_displacement(mov2_mem_source, 0);
                    xed_uint_t disp_width_bits = xed_decoded_inst_get_memory_displacement_width_bits(mov2_mem_source, 0);
                    // RIP-relative loads encode a PC-relative displacement, and
                    // SHLX at rewrite_offset lands at a different byte than MOV2
                    // did. Shift the displacement by the address delta so the
                    // target stays the same. SHLX with RIP-relative memory is
                    // always 9 bytes (3-byte VEX + F7 + ModR/M + disp32).
                    if (mem_base == XED_REG_RIP || mem_base == XED_REG_EIP) {
                        static const int shlx_rip_len = 9;
                        int64_t target = (int64_t)mov2_source_offset +
                                         (int64_t)mov2_source_len + disp;
                        disp = target - (int64_t)rewrite_offset - shlx_rip_len;
                        disp_width_bits = 32;
                    }
                    op_rm = xed_mem_gbisd(
                            xed_decoded_inst_get_seg_reg(mov2_mem_source, 0),
                            mem_base,
                            xed_decoded_inst_get_index_reg(mov2_mem_source, 0),
                            xed_decoded_inst_get_scale(mov2_mem_source, 0),
                            xed_disp(disp, disp_width_bits),
                            mem_width_bits);
                } else {
                    op_rm = xed_reg(shlx_rm);
                }

                xed_encoder_instruction_t enc_inst;
                xed_inst3(&enc_inst, state, new_iclass, eow,
                          xed_reg(shift_dst), op_rm, xed_reg(mov_src));

                xed_encoder_request_t req;
                xed_encoder_request_zero_set_mode(&req, &state);
                if (!xed_convert_to_encoder_request(&req, &enc_inst)) {
                    fprintf(stderr, "Could not convert SHLX request\n");
                    goto end;
                }
                xed_error_enum_t err = xed_encode(&req, new_bytes, sizeof(new_bytes), &new_len);
                if (err != XED_ERROR_NONE) {
                    fprintf(stderr, "Could not encode instruction: %s\n", xed_error_enum_t2str(err));
                    char buf[1024];
                    xed_encode_request_print(&req, buf, sizeof(buf));
                    fprintf(stderr, "%s\n", buf);
                    goto end;
                }

                unsigned int old_len = (offset + xed_decoded_inst_get_length(&xedd)) - rewrite_offset;
                VLOG("Replacement instruction is %u bytes and original instructions are %u bytes\n", new_len, old_len);
                if (new_len > old_len) {
                    VLOG("Cannot replace instructions since replacement is too large\n");
                    goto end;
                }
                if (target_in_interior(branch_targets, rewrite_offset,
                                       offset + xed_decoded_inst_get_length(&xedd))) {
                    VLOG("Branch target inside rewrite range [%zu, %zu); skipping\n",
                            rewrite_offset, offset + xed_decoded_inst_get_length(&xedd));
                    goto end;
                }

                xed_decoded_inst_t xedd_tmp;
                xed_decoded_inst_zero(&xedd_tmp);
                xed_decoded_inst_set_mode(&xedd_tmp, mmode, stack_addr_width);
                err = xed_decode(&xedd_tmp, new_bytes, sizeof(new_bytes));
                if (err != XED_ERROR_NONE) {
                    return -1;
                }
                char buffer[256];
                xed_bool_t ok = xed_format_context(
                        XED_SYNTAX_ATT, &xedd_tmp, buffer, sizeof(buffer),
                        offset,  // IP address (for relative branch calculation) TODO: this seems incorrect
                        /*context=*/ NULL, /*symbolic_callback=*/ NULL);
                if (ok) {
                    printf("R %s [%u bytes]\n", buffer, xed_decoded_inst_get_length(&xedd_tmp));
                }
                ++count;

                // TODO: consider that shift distance may be > 31 for ECX or > 63 for RCX

                if (replace) {
                    uint8_t *addr = inst + rewrite_offset;
                    memcpy(addr, new_bytes, new_len);

                    if (old_len - new_len > 0) {
                        err = xed_encode_nop(addr + new_len, old_len - new_len);
                        if (err != XED_ERROR_NONE) {
                            fprintf(stderr, "Could not encode no-ops: %s\n", xed_error_enum_t2str(err));
                            return -1;
                        }
                    }
                }
            } else {
                VLOG("Replacement not possible ecx_written: %d eflags_written: %d\n", ecx_written, eflags_written);
            }
        }

end:
        if (is_basic_block_terminator(&xedd)) {
            history_reset(&history);
        } else {
            history_push(&history, &xedd, offset);
        }
        offset += xed_decoded_inst_get_length(&xedd);
    }

    return count;
}

static int check_andn_impl(uint8_t *inst, size_t len, bool replace,
                            const uint8_t *branch_targets);

int check_andn(uint8_t *inst, size_t len, bool replace)
{
    size_t bitmap_bytes = len > 0 ? (len + 7) / 8 : 1;
    uint8_t *targets = calloc(bitmap_bytes, 1);
    if (targets == NULL) {
        return -1;
    }
    collect_branch_targets(inst, len, targets);
    int result = check_andn_impl(inst, len, replace, targets);
    free(targets);
    return result;
}

// Rewrite `not %reg_A; and %reg_A, %reg_B` as `andn %reg_A, %reg_B, %reg_B`.
// ANDN reads the un-negated value of reg_A directly, so after the rewrite
// reg_A holds its original value rather than the inverted one; we refuse
// unless reg_A is overwritten before any subsequent read. ANDN also leaves PF
// undefined whereas AND sets it based on the result, so PF must be clobbered
// before any read. CF/OF/SF/ZF are written identically by both.
static int check_andn_impl(uint8_t *inst, size_t len, bool replace,
                            const uint8_t *branch_targets)
{
    int count = 0;
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;
    struct inst_history history;
    history_reset(&history);

    // PF is bit 2 of xed_flag_set_t.flat.
    const uint32_t pf_bit = 1u << 2;

    for (size_t offset = 0; offset < len;) {
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);

        xed_error_enum_t err = xed_decode(&xedd, inst + offset, len - offset);
        if (err != XED_ERROR_NONE) {
            fprintf(stderr, "Decoding error at offset: %zu: %s\n", offset,
                    xed_error_enum_t2str(err));
            return -1;
        }

        if (xed_decoded_inst_get_iclass(&xedd) != XED_ICLASS_AND) {
            goto end;
        }
        if (xed_decoded_inst_number_of_memory_operands(&xedd) != 0 ||
            xed_decoded_inst_get_immediate_width_bits(&xedd) != 0) {
            goto end;
        }

        // Extract AND's two register operands. The EFLAGS write is also an
        // operand; skip it by register name. Anything else bails.
        const xed_inst_t *xi = xed_decoded_inst_inst(&xedd);
        unsigned int n = xed_inst_noperands(xi);
        xed_reg_enum_t and_dst = XED_REG_INVALID;
        xed_reg_enum_t and_src = XED_REG_INVALID;
        bool form_ok = true;
        for (unsigned int i = 0; form_ok && i < n; i++) {
            const xed_operand_t *op = xed_inst_operand(xi, i);
            xed_operand_enum_t op_name = xed_operand_name(op);
            xed_operand_action_enum_t act = xed_operand_rw(op);
            if (!xed_operand_is_register(op_name)) {
                form_ok = false;
                continue;
            }
            xed_reg_enum_t reg = xed_decoded_inst_get_reg(&xedd, op_name);
            if (reg == XED_REG_EFLAGS || reg == XED_REG_RFLAGS ||
                reg == XED_REG_FLAGS) {
                continue;
            }
            if (act == XED_OPERAND_ACTION_RW) {
                and_dst = reg;
            } else if (act == XED_OPERAND_ACTION_R) {
                and_src = reg;
            } else {
                form_ok = false;
            }
        }
        if (!form_ok || and_dst == XED_REG_INVALID || and_src == XED_REG_INVALID) {
            goto end;
        }

        // Find an adjacent preceding NOT on one of AND's source operands.
        const struct inst_history_entry *not_entry = history_at(&history, 1);
        if (not_entry == NULL) {
            goto end;
        }
        if (xed_decoded_inst_get_iclass(&not_entry->xedd) != XED_ICLASS_NOT) {
            goto end;
        }
        if (xed_decoded_inst_number_of_memory_operands(&not_entry->xedd) != 0) {
            goto end;
        }
        if (not_entry->offset + xed_decoded_inst_get_length(&not_entry->xedd) != offset) {
            goto end;
        }

        const xed_inst_t *xi_not = xed_decoded_inst_inst(&not_entry->xedd);
        xed_reg_enum_t not_reg = XED_REG_INVALID;
        if (xed_inst_noperands(xi_not) >= 1) {
            const xed_operand_t *op = xed_inst_operand(xi_not, 0);
            if (xed_operand_is_register(xed_operand_name(op)) &&
                xed_operand_rw(op) == XED_OPERAND_ACTION_RW) {
                not_reg = xed_decoded_inst_get_reg(&not_entry->xedd,
                                                    xed_operand_name(op));
            }
        }
        if (not_reg == XED_REG_INVALID) {
            goto end;
        }

        // We currently handle pattern 2 only: NOT's register is AND's R-only
        // source. The other case (NOT's register == AND's dst) is rarer and
        // less clean to encode (REG0 and REG1 would share a register).
        if (xed_get_largest_enclosing_register(not_reg) !=
            xed_get_largest_enclosing_register(and_src)) {
            goto end;
        }
        xed_reg_enum_t mask_reg = and_src;
        xed_reg_enum_t other_reg = and_dst;

        // The mask and the other operand must be distinct registers. For
        // `and %reg,%reg` (and_src == and_dst) the rewrite would emit
        // `andn %reg,%reg,%reg`, i.e. ~reg & reg == 0 unconditionally (and
        // ZF forced to 1), whereas `not %reg; and %reg,%reg` leaves reg = ~reg.
        if (xed_get_largest_enclosing_register(mask_reg) ==
            xed_get_largest_enclosing_register(other_reg)) {
            goto end;
        }

        unsigned int eow = xed_get_register_width_bits(and_dst);
        if (eow != 32 && eow != 64) {
            goto end;
        }

        // The NOT and the AND must operate on the same width. A narrower NOT
        // zero-extends its result into the wider register, so e.g.
        // `not %eax; and %rax,%rbx` clears rbx[63:32]; folding to a 64-bit
        // `andn` would instead read the full, un-zero-extended rax and leave
        // those high bits set. (enclosing-register equality above is not
        // enough -- it treats EAX and RAX as the same operand.)
        if (xed_get_register_width_bits(not_reg) != eow) {
            goto end;
        }

        // Forward lookahead: mask_reg must be fully overwritten before any
        // read, and PF must be overwritten before any PF read.
        bool mask_killed = false;
        uint32_t killed_flags = 0;
        size_t new_offset = offset + xed_decoded_inst_get_length(&xedd);
        for (int i = 0; i < 16 && new_offset < len; i++) {
            xed_decoded_inst_t xedd_new;
            xed_decoded_inst_zero(&xedd_new);
            xed_decoded_inst_set_mode(&xedd_new, mmode, stack_addr_width);
            err = xed_decode(&xedd_new, inst + new_offset, len - new_offset);
            if (err != XED_ERROR_NONE) {
                return -1;
            }
            if (is_branch_bailout(&xedd_new)) {
                goto end;
            }
            bool w = false, r = false;
            inst_touches_reg(&xedd_new, mask_reg, &w, &r);
            bool zeroing = is_zeroing_idiom_on(&xedd_new, mask_reg);
            if (r && !zeroing && !mask_killed) {
                goto end;
            }
            uint32_t read_mask = read_rflags_mask(&xedd_new);
            if ((read_mask & pf_bit & ~killed_flags) != 0) {
                goto end;
            }
            if (kills_reg_full(&xedd_new, mask_reg)) {
                mask_killed = true;
            }
            killed_flags |= written_rflags_mask(&xedd_new);
            if (mask_killed && (pf_bit & ~killed_flags) == 0) {
                break;
            }
            new_offset += xed_decoded_inst_get_length(&xedd_new);
        }
        if (!mask_killed || (pf_bit & ~killed_flags) != 0) {
            goto end;
        }

        // Encode ANDN via the high-level builder.
        xed_state_t state;
        xed_state_zero(&state);
        state.mmode = XED_MACHINE_MODE_LONG_64;
        state.stack_addr_width = XED_ADDRESS_WIDTH_64b;
        xed_encoder_instruction_t enc_inst;
        xed_inst3(&enc_inst, state, XED_ICLASS_ANDN, eow,
                  xed_reg(and_dst), xed_reg(mask_reg), xed_reg(other_reg));
        xed_encoder_request_t req;
        xed_encoder_request_zero_set_mode(&req, &state);
        if (!xed_convert_to_encoder_request(&req, &enc_inst)) {
            goto end;
        }
        uint8_t new_bytes[XED_MAX_INSTRUCTION_BYTES];
        unsigned int new_len = 0;
        xed_error_enum_t enc_err = xed_encode(&req, new_bytes, sizeof(new_bytes),
                                               &new_len);
        if (enc_err != XED_ERROR_NONE) {
            goto end;
        }

        unsigned int old_len = (offset + xed_decoded_inst_get_length(&xedd)) -
                               not_entry->offset;
        if (new_len > old_len) {
            goto end;
        }
        size_t rewrite_end = offset + xed_decoded_inst_get_length(&xedd);
        if (target_in_interior(branch_targets, not_entry->offset, rewrite_end)) {
            goto end;
        }

        printf("R andn %s, %s, %s [%u bytes, replacing %u]\n",
                xed_reg_enum_t2str(and_dst), xed_reg_enum_t2str(mask_reg),
                xed_reg_enum_t2str(other_reg), new_len, old_len);
        ++count;

        if (replace) {
            uint8_t *addr = inst + not_entry->offset;
            memcpy(addr, new_bytes, new_len);
            if (old_len > new_len) {
                enc_err = xed_encode_nop(addr + new_len, old_len - new_len);
                if (enc_err != XED_ERROR_NONE) {
                    return -1;
                }
            }
        }

end:
        if (is_basic_block_terminator(&xedd)) {
            history_reset(&history);
        } else {
            history_push(&history, &xedd, offset);
        }
        offset += xed_decoded_inst_get_length(&xedd);
    }
    return count;
}
