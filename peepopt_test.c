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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "peepopt.h"
#include "xed/xed-interface.h"

#define CHECK_BYTES(func, ...) \
do { \
    uint8_t bytes[] = { __VA_ARGS__ }; \
    assert(func(bytes, sizeof(bytes), /*replace=*/ false)); \
} while (0)

int main(int argc, char *argv[])
{
    xed_tables_init();
    xed_set_verbosity(99);

    CHECK_BYTES(
        !check_shifts,
        0x89, 0xF8,        // movl %edi,%eax
        0x89, 0xF1,        // movl %esi,%ecx
        0xD3, 0xE0,        // sall %cl,%eax
    );
    CHECK_BYTES(
        !check_shifts,
        0x89, 0xF8,        // movl %edi,%eax
        0x89, 0xF1,        // movl %esi,%ecx
        0xD3, 0xE0,        // sall %cl,%eax
        0xC3               // ret
    );
    CHECK_BYTES(
        check_shifts,
        0x89, 0xF8,        // movl %edi,%eax
        0x44, 0x89, 0xC1,  // movl %r8d,%ecx
        0xD3, 0xE0,        // sall %cl,%eax
        0xC3               // ret
    );
    // TODO: test reads and writes of ECX and EFLAGS

    return 0;
}
