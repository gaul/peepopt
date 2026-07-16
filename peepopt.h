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

#ifndef __PEEPOPT_H__
#define __PEEPOPT_H__

#include <stdint.h>
#include <unistd.h>

// A read-only data section (e.g. .rodata, .data.rel.ro) that may contain
// switch jump tables referencing .text.
struct peepopt_data_section {
    const uint8_t *bytes;
    uint64_t vaddr;
    size_t size;
};

// Optional image-level context for branch-target collection. When present,
// the rewrite passes additionally treat as branch targets: entries of
// int32-relative jump tables reachable from RIP-relative LEAs into the data
// sections, entries of absolute jump tables referenced by memory-indirect
// JMPs, and the code addresses supplied in extra_targets (relocation-derived
// pointers, exception landing pads). Passing NULL only protects direct
// Jcc/JMP/CALL targets.
struct peepopt_ctx {
    uint64_t text_vaddr;
    const struct peepopt_data_section *data_sections;  // .rodata, .data.rel.ro
    size_t num_data_sections;
    const uint64_t *extra_targets;  // VAs inside .text: RELA/RELR, landing pads
    size_t num_extra_targets;
};

void peepopt_set_verbose(bool verbose);
void peepopt_print_stats(void);
int check_shifts(uint8_t *inst, size_t len, bool replace,
                 const struct peepopt_ctx *ctx);
int check_andn(uint8_t *inst, size_t len, bool replace,
               const struct peepopt_ctx *ctx);
int check_vex3(uint8_t *inst, size_t len, bool replace,
               const struct peepopt_ctx *ctx);
int check_apx(uint8_t *inst, size_t len, bool replace,
              const struct peepopt_ctx *ctx);

#endif
