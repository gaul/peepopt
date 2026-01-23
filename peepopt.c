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

int check_shifts(uint8_t *inst, size_t len, bool replace)
{
    int count = 0;
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;
    xed_decoded_inst_t xedd_old;

    for (size_t offset = 0; offset < len;) {
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);

        xed_error_enum_t err = xed_decode(&xedd, inst + offset, len - offset);
        if (err != XED_ERROR_NONE) {
            printf("Decoding error at offset: %zu: %s\n", offset, xed_error_enum_t2str(err));
            return -1;
        }

        char buffer[256];
        xed_bool_t ok = xed_format_context(
                XED_SYNTAX_ATT, &xedd, buffer, sizeof(buffer),
                offset,  // IP address (for relative branch calculation) TODO: this seems incorrect
                /*context=*/ NULL, /*symbolic_callback=*/ NULL);
        if (ok) {
            printf("* %s [%u bytes]\n", buffer, xed_decoded_inst_get_length(&xedd));
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
            int oldiclass = xed_decoded_inst_get_iclass(&xedd_old);
            if (oldiclass != XED_ICLASS_MOV) {
                goto end;
            }

            printf("Examining MOV + shift pair\n");

            xed_reg_enum_t shift_src = XED_REG_INVALID;
            xed_reg_enum_t shift_dst = XED_REG_INVALID;
            xed_reg_enum_t mov_src = XED_REG_INVALID;
            xed_reg_enum_t mov_dst = XED_REG_INVALID;

            // Previous MOV
            // TODO: possible to merge one other MOV due to three-operand instructions?
            const xed_inst_t* xi = xed_decoded_inst_inst(&xedd_old);
            unsigned int noperands = xed_inst_noperands(xi);
            for (unsigned int i = 0; i < noperands; i++) {
                const xed_operand_t *op = xed_inst_operand(xi, i);
                xed_operand_enum_t op_name = xed_operand_name(op);
                if (!xed_operand_is_register(op_name))
                    goto end;

                xed_operand_action_enum_t action = xed_operand_rw(op);
                xed_reg_enum_t reg = xed_decoded_inst_get_reg(&xedd_old, xed_operand_name(op));
                printf("mov   operand %u %s action register %s\n", i, xed_operand_action_enum_t2str(action), xed_reg_enum_t2str(reg));

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
                printf("shift operand %u %s action register %s\n", i, xed_operand_action_enum_t2str(action), xed_reg_enum_t2str(reg));

                if (action == XED_OPERAND_ACTION_R) {
                    shift_src = reg;
                } else if (action == XED_OPERAND_ACTION_RW || action == XED_OPERAND_ACTION_W) {
                    if (xed_get_register_width_bits(reg) < 32) {
                        printf("Ignore partial registers\n");
                        goto end;
                    }
                    shift_dst = reg;
                } else if (action == XED_OPERAND_ACTION_CW) {
                    // ignore FLAGS
                } else {
                    goto end;
                }
            }

            printf("MOV src: %s MOV dst: %s SHR src: %s SHR dst: %s\n",
                    xed_reg_enum_t2str(mov_src), xed_reg_enum_t2str(mov_dst),
                    xed_reg_enum_t2str(shift_src), xed_reg_enum_t2str(shift_dst));
            // TODO: check that the source and dest operands and widths match
            if (!((mov_dst == XED_REG_ECX || mov_dst == XED_REG_RCX) && shift_src == XED_REG_CL)) {
                printf("Wrong register pairs for replacement\n");
                goto end;
            }

            if (xed_get_register_width_bits(shift_dst) == 64 &&
                    xed_get_register_width_bits(mov_src) == 32) {
                // Promote 32-bit register sources to 64-bit
                // TODO: is this always safe?
                mov_src = mov_src - XED_REG_EAX + XED_REG_RAX;
            }

            printf("Higher confidence\n");

            // Look ahead at subsequent instructions to see if both RCX and RFLAGS are overwritten.
            bool ecx_written = false;
            bool eflags_written = false;

            size_t new_offset = offset + xed_decoded_inst_get_length(&xedd);
            for (int i = 0; i < 16 && new_offset < len; ++i) {
                xed_decoded_inst_t xedd_new;
                xed_decoded_inst_zero(&xedd_new);
                xed_decoded_inst_set_mode(&xedd_new, mmode, stack_addr_width);
                err = xed_decode(&xedd_new, inst + new_offset, len - new_offset);
                if (err != XED_ERROR_NONE) {
                    printf("Decoding error at offset: %zu: %s\n", new_offset, xed_error_enum_t2str(err));
                    return -1;
                }

                ok = xed_format_context(
                        XED_SYNTAX_ATT, &xedd_new, buffer, sizeof(buffer),
                        offset,  // IP address (for relative branch calculation) TODO: this seems incorrect
                        /*context=*/ NULL, /*symbolic_callback=*/ NULL);
                if (ok) {
                    printf("* %s [%u bytes]\n", buffer, xed_decoded_inst_get_length(&xedd_new));
                }

                xi = xed_decoded_inst_inst(&xedd_new);
                noperands = xed_inst_noperands(xi);
                switch (xed_decoded_inst_get_iclass(&xedd_new)) {
                case XED_ICLASS_CALL_NEAR:
                case XED_ICLASS_CALL_FAR:
                    printf("CALL clobbers ECX\n");
                    ecx_written = true;
                    break;
                case XED_ICLASS_RET_NEAR:
                case XED_ICLASS_RET_FAR:
                    printf("RET clobbers ECX and EFLAGS\n");
                    ecx_written = true;
                    eflags_written = true;
                    break;
                case XED_ICLASS_XOR:
                    if (noperands == 3) {
                        // handle xor %ecx, %ecx
                        xed_operand_action_enum_t actions[3];
                        xed_reg_enum_t regs[3];
                        for (unsigned int i = 0; i < noperands; ++i) {
                            const xed_operand_t *op = xed_inst_operand(xi, i);
                            actions[i] = xed_operand_rw(op);
                            regs[i] = xed_decoded_inst_get_reg(&xedd_new, xed_operand_name(op));
                        }
                        if (actions[0] == XED_OPERAND_ACTION_RW && (regs[0] == XED_REG_ECX || regs[0] == XED_REG_RCX) &&
                            actions[1] == XED_OPERAND_ACTION_R  && (regs[1] == XED_REG_ECX || regs[1] == XED_REG_RCX) &&
                            actions[2] == XED_OPERAND_ACTION_W  && (regs[2] == XED_REG_EFLAGS || regs[2] == XED_REG_RFLAGS)) {
                            printf("Zeroing idiom on ECX\n");
                            ecx_written = true;
                            eflags_written = true;
                        }
                    }
                    break;
                case XED_ICLASS_JB:
                case XED_ICLASS_JBE:
                case XED_ICLASS_JCXZ:
                case XED_ICLASS_JECXZ:
                case XED_ICLASS_JL:
                case XED_ICLASS_JLE:
                case XED_ICLASS_JMP:
                case XED_ICLASS_JMPABS:
                case XED_ICLASS_JMP_FAR:
                case XED_ICLASS_JNB:
                case XED_ICLASS_JNBE:
                case XED_ICLASS_JNL:
                case XED_ICLASS_JNLE:
                case XED_ICLASS_JNO:
                case XED_ICLASS_JNP:
                case XED_ICLASS_JNS:
                case XED_ICLASS_JNZ:
                case XED_ICLASS_JO:
                case XED_ICLASS_JP:
                case XED_ICLASS_JRCXZ:
                case XED_ICLASS_JS:
                case XED_ICLASS_JZ:
                    // Once control flow changes it is difficult to track liveness of ECX and EFLAGS
                    printf("Branch, cannot replace\n");
                    goto end;
                default:
                    // ignore
                    break;
                }
                // TODO: consider a pattern of neg %ecx

                for (unsigned int i = 0; i < noperands; i++) {
                    const xed_operand_t *op = xed_inst_operand(xi, i);
                    xed_operand_action_enum_t action = xed_operand_rw(op);
                    xed_reg_enum_t reg = xed_decoded_inst_get_reg(&xedd_new, xed_operand_name(op));
                    printf("???   operand %u action %s register %s\n", i, xed_operand_action_enum_t2str(action), xed_reg_enum_t2str(reg));

                    if (action == XED_OPERAND_ACTION_R ||
                        action == XED_OPERAND_ACTION_RW ||
                        action == XED_OPERAND_ACTION_RCW ||
                        action == XED_OPERAND_ACTION_CR) {
                        if (!ecx_written && (reg == XED_REG_ECX || reg == XED_REG_RCX)) {
                            printf("Reading from ECX, cannot replace\n");
                            goto end;
                        } else if (!eflags_written && (reg == XED_REG_FLAGS || reg == XED_REG_EFLAGS || reg == XED_REG_RFLAGS)) {
                            printf("Reading from EFLAGS, cannot replace\n");
                            goto end;
                        }
                    } else if (action == XED_OPERAND_ACTION_W) {
                        // if writing to ECX then replacement may be possible
                        if (reg == XED_REG_ECX || reg == XED_REG_RCX) {
                            printf("Writing to ECX, replacement may be possible\n");
                            ecx_written = true;
                        }
                        if (reg == XED_REG_FLAGS || reg == XED_REG_EFLAGS || reg == XED_REG_RFLAGS) {
                            printf("Writing to EFLAGS, replacement may be possible\n");
                            eflags_written = true;
                        }
                    }
                }

                if (ecx_written && eflags_written) {
                    break;
                }

                new_offset += xed_decoded_inst_get_length(&xedd_new);
            }

            if (ecx_written && eflags_written) {
                // assemble replacement instruction
                printf("Highest confidence that replacement is possible\n");
                uint8_t new_bytes[XED_MAX_INSTRUCTION_BYTES];
                unsigned new_len = 0;
                xed_state_t state;
                xed_state_zero(&state);
                state.mmode = XED_MACHINE_MODE_LONG_64;
                state.stack_addr_width = XED_ADDRESS_WIDTH_64b;

                xed_encoder_request_t req;
                xed_encoder_request_zero_set_mode(&req, &state);
                xed_encoder_request_set_iclass(&req,
                        iclass == XED_ICLASS_SHL ? XED_ICLASS_SHLX :
                        iclass == XED_ICLASS_SHR ? XED_ICLASS_SHRX :
                        iclass == XED_ICLASS_SAR ? XED_ICLASS_SARX :
                                                   XED_ICLASS_INVALID);
                xed_encoder_request_set_effective_operand_width(&req, xed_get_register_width_bits(shift_dst));
                xed_encoder_request_set_reg(&req, XED_OPERAND_REG0, shift_dst);
                xed_encoder_request_set_operand_order(&req, 0, XED_OPERAND_REG0);
                xed_encoder_request_set_reg(&req, XED_OPERAND_REG1, shift_dst);
                xed_encoder_request_set_operand_order(&req, 1, XED_OPERAND_REG1);
                xed_encoder_request_set_reg(&req, XED_OPERAND_REG2, mov_src);
                xed_encoder_request_set_operand_order(&req, 2, XED_OPERAND_REG2);
                xed_error_enum_t err = xed_encode(&req, new_bytes, sizeof(new_bytes), &new_len);
                if (err != XED_ERROR_NONE) {
                    printf("Could not encode instruction: %s\n", xed_error_enum_t2str(err));
                    char buf[1024];
                    xed_encode_request_print(&req, buf, sizeof(buf));
                    printf("%s\n", buf);
                    goto end;
                }

                unsigned int old_len = xed_decoded_inst_get_length(&xedd) + xed_decoded_inst_get_length(&xedd_old);
                printf("Replacement instruction is %u bytes and original instructions are %u bytes\n", new_len, old_len);
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
                if (new_len <= old_len) {
                    ++count;
                } else {
                    printf("Cannot replace instructions since replacement is too large\n");
                    goto end;
                }

                // TODO: consider that shift distance may be > 31 for ECX or > 63 for RCX

                if (replace) {
                    uint8_t *addr = inst + offset - xed_decoded_inst_get_length(&xedd_old);
                    memcpy(addr, new_bytes, new_len);

                    if (old_len - new_len > 0) {
                        err = xed_encode_nop(addr + new_len, old_len - new_len);
                        if (err != XED_ERROR_NONE) {
                            printf("Could not encode no-ops: %s\n", xed_error_enum_t2str(err));
                            return -1;
                        }
                    }
                }
            } else {
                printf("Replacement not possible ecx_written: %d eflags_written: %d\n", ecx_written, eflags_written);
            }
        }

end:
        xedd_old = xedd;
        offset += xed_decoded_inst_get_length(&xedd);
    }

    return count;
}
