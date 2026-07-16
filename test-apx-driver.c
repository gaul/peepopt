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

// Driver for test-apx-fixture.S: prints every fixture's result over inputs
// chosen to exercise carry, borrow, sign, and overflow edges. test-apx.sh
// diffs this output before and after `peepopt -m apx` rewrites the fixtures.

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

uint64_t apx_add64(uint64_t x, uint64_t y);
uint64_t apx_sub64(uint64_t x, uint64_t y);
uint64_t apx_add_same(uint64_t x);
uint32_t apx_xor32_ext(uint32_t x, uint32_t y);
uint32_t apx_add32_norex(uint32_t x, uint32_t y);
uint64_t apx_mem64(const uint64_t *p, uint64_t y);
uint64_t apx_adc64(uint64_t a, uint64_t b, uint64_t x, uint64_t y);
uint64_t apx_flags_after(uint64_t x, uint64_t y);
uint64_t apx_cmov(uint64_t a, uint64_t b, uint64_t x, uint64_t y);
uint64_t apx_imul(uint64_t x, uint64_t y);
uint64_t apx_imm(uint64_t x);
uint64_t apx_neg64(uint64_t x);
uint64_t apx_not64(uint64_t x);
uint64_t apx_inc64(uint64_t x, uint64_t y);
uint64_t apx_shl_imm(uint64_t x);
uint64_t apx_rol_imm(uint64_t x);
uint64_t apx_shr_cl(uint64_t x, uint64_t u1, uint64_t u2, uint64_t count);
uint64_t apx_load_add(const uint64_t *p, uint64_t y);
uint64_t apx_load_sub_imm(const uint64_t *p);
uint64_t apx_load_neg(const uint64_t *p);
uint64_t apx_load_shl(const uint64_t *p);
uint64_t apx_load_cmov(const uint64_t *p, uint64_t a, uint64_t b, uint64_t c);
uint64_t apx_load_selfptr(const uint64_t *p, uint64_t y);
uint64_t apx_setzu(uint64_t x, uint64_t y);
uint64_t apx_setzu_ext(uint64_t x, uint64_t y);
uint64_t apx_switch(uint64_t sel, uint64_t x, uint64_t y);

int main(void)
{
    static const uint64_t inputs[] = {
        0, 1, 2, 100, UINT64_MAX, UINT64_MAX - 1,
        1ull << 63, (1ull << 63) - 1, 1ull << 32,
        0x123456789ABCDEF0ull, 0xFFFFFFFF00000000ull, 0x00000000FFFFFFFFull,
    };
    const size_t n = sizeof(inputs) / sizeof(inputs[0]);
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < n; j++) {
            const uint64_t x = inputs[i];
            const uint64_t y = inputs[j];
            printf("add64(%" PRIx64 ",%" PRIx64 ")=%" PRIx64 "\n",
                   x, y, apx_add64(x, y));
            printf("sub64=%" PRIx64 "\n", apx_sub64(x, y));
            printf("add_same=%" PRIx64 "\n", apx_add_same(x));
            printf("xor32=%" PRIx32 "\n",
                   apx_xor32_ext((uint32_t)x, (uint32_t)y));
            printf("add32=%" PRIx32 "\n",
                   apx_add32_norex((uint32_t)x, (uint32_t)y));
            const uint64_t mem = y;
            printf("mem64=%" PRIx64 "\n", apx_mem64(&mem, x));
            printf("adc64=%" PRIx64 "\n", apx_adc64(x, y, y, x));
            printf("flags_after=%" PRIx64 "\n", apx_flags_after(x, y));
            printf("cmov=%" PRIx64 "\n", apx_cmov(x, y, x + 1, y + 1));
            printf("imul=%" PRIx64 "\n", apx_imul(x, y));
            printf("imm=%" PRIx64 "\n", apx_imm(x));
            printf("neg64=%" PRIx64 "\n", apx_neg64(x));
            printf("not64=%" PRIx64 "\n", apx_not64(x));
            printf("inc64=%" PRIx64 "\n", apx_inc64(x, y));
            printf("shl_imm=%" PRIx64 "\n", apx_shl_imm(x));
            printf("rol_imm=%" PRIx64 "\n", apx_rol_imm(x));
            printf("shr_cl=%" PRIx64 "\n", apx_shr_cl(x, 0, 0, y));
            printf("load_add=%" PRIx64 "\n", apx_load_add(&mem, x));
            printf("load_sub_imm=%" PRIx64 "\n", apx_load_sub_imm(&mem));
            printf("load_neg=%" PRIx64 "\n", apx_load_neg(&mem));
            printf("load_shl=%" PRIx64 "\n", apx_load_shl(&mem));
            printf("load_cmov=%" PRIx64 "\n",
                   apx_load_cmov(&mem, x, y, x ^ y));
            printf("load_selfptr=%" PRIx64 "\n", apx_load_selfptr(&mem, x));
            printf("setzu=%" PRIx64 "\n", apx_setzu(x, y));
            printf("setzu_ext=%" PRIx64 "\n", apx_setzu_ext(x, y));
            for (uint64_t sel = 0; sel < 4; sel++) {
                printf("switch(%" PRIu64 ")=%" PRIx64 "\n",
                       sel, apx_switch(sel, x, y));
            }
        }
    }
    return 0;
}
