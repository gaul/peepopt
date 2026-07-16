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

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "peepopt.h"
#include "xed/xed-interface.h"

// An executable section's virtual address range; relocation-derived pointers
// are only interesting when they land in one of these.
struct exec_range {
    uint64_t lo;
    uint64_t hi;
};

static bool va_in_exec(const struct exec_range *ranges, size_t n, uint64_t va)
{
    for (size_t i = 0; i < n; ++i) {
        if (va >= ranges[i].lo && va < ranges[i].hi) {
            return true;
        }
    }
    return false;
}

// Append to a realloc-doubling array. Returns false on allocation failure.
static bool append_va(uint64_t **arr, size_t *n, size_t *cap, uint64_t va)
{
    if (*n == *cap) {
        size_t new_cap = *cap == 0 ? 1024 : *cap * 2;
        uint64_t *p = realloc(*arr, new_cap * sizeof(**arr));
        if (p == NULL) {
            return false;
        }
        *arr = p;
        *cap = new_cap;
    }
    (*arr)[(*n)++] = va;
    return true;
}

// Map a virtual address to its file bytes by finding the SHF_ALLOC section
// containing it. Returns NULL if unmapped or fewer than `need` bytes remain.
// When `avail` is non-NULL it receives the bytes remaining in the section.
static const uint8_t *va_to_file(const uint8_t *file, size_t file_size,
                                 const Elf64_Ehdr *eh, uint64_t va,
                                 size_t need, size_t *avail)
{
    for (uint32_t i = 0; i < eh->e_shnum; ++i) {
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(file + eh->e_shoff +
                (uint64_t)i * eh->e_shentsize);
        if (!(sh->sh_flags & SHF_ALLOC) || sh->sh_type == SHT_NOBITS) {
            continue;
        }
        if (va < sh->sh_addr || va - sh->sh_addr >= sh->sh_size ||
            sh->sh_size - (va - sh->sh_addr) < need) {
            continue;
        }
        if (sh->sh_offset > file_size ||
            sh->sh_size > file_size - sh->sh_offset) {
            continue;
        }
        if (avail != NULL) {
            *avail = sh->sh_size - (va - sh->sh_addr);
        }
        return file + sh->sh_offset + (va - sh->sh_addr);
    }
    return NULL;
}

// A RELR-relocated slot holds a link-time code pointer for ET_DYN objects.
// Read it and record it if it points into an executable section. Returns
// false on allocation failure.
static bool add_relr_slot(const uint8_t *file, size_t file_size,
                          const Elf64_Ehdr *eh,
                          const struct exec_range *exec, size_t num_exec,
                          uint64_t slot_va,
                          uint64_t **arr, size_t *n, size_t *cap)
{
    const uint8_t *p = va_to_file(file, file_size, eh, slot_va,
                                  sizeof(uint64_t), NULL);
    if (p == NULL) {
        return true;  // unmapped slot: nothing to record
    }
    uint64_t value;
    memcpy(&value, p, sizeof(value));
    if (!va_in_exec(exec, num_exec, value)) {
        return true;
    }
    return append_va(arr, n, cap, value);
}

// DWARF exception-header pointer encodings (the subset gcc/clang emit).
#define DW_EH_PE_absptr   0x00
#define DW_EH_PE_uleb128  0x01
#define DW_EH_PE_udata2   0x02
#define DW_EH_PE_udata4   0x03
#define DW_EH_PE_udata8   0x04
#define DW_EH_PE_sleb128  0x09
#define DW_EH_PE_sdata2   0x0A
#define DW_EH_PE_sdata4   0x0B
#define DW_EH_PE_sdata8   0x0C
#define DW_EH_PE_pcrel    0x10
#define DW_EH_PE_indirect 0x80
#define DW_EH_PE_omit     0xFF

// Bounds-checked reader over a byte range whose virtual address is tracked
// so pcrel-encoded pointers can be resolved.
struct eh_cursor {
    const uint8_t *p;
    const uint8_t *end;
    uint64_t va;
};

static bool cur_u8(struct eh_cursor *c, uint8_t *out)
{
    if (c->end - c->p < 1) {
        return false;
    }
    *out = *c->p++;
    c->va++;
    return true;
}

static bool cur_bytes(struct eh_cursor *c, void *out, size_t n)
{
    if ((size_t)(c->end - c->p) < n) {
        return false;
    }
    memcpy(out, c->p, n);
    c->p += n;
    c->va += n;
    return true;
}

static bool cur_uleb(struct eh_cursor *c, uint64_t *out)
{
    uint64_t result = 0;
    int shift = 0;
    while (c->p < c->end) {
        uint8_t byte = *c->p++;
        c->va++;
        if (shift < 64) {
            result |= (uint64_t)(byte & 0x7F) << shift;
        }
        shift += 7;
        if ((byte & 0x80) == 0) {
            *out = result;
            return true;
        }
    }
    return false;
}

static bool cur_sleb(struct eh_cursor *c, int64_t *out)
{
    uint64_t result = 0;
    int shift = 0;
    while (c->p < c->end) {
        uint8_t byte = *c->p++;
        c->va++;
        if (shift < 64) {
            result |= (uint64_t)(byte & 0x7F) << shift;
        }
        shift += 7;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40)) {
                result |= ~UINT64_C(0) << shift;
            }
            *out = (int64_t)result;
            return true;
        }
    }
    return false;
}

// Read the value portion of an encoded pointer (the low-nibble format),
// without applying the high-nibble base. Used to skip fields and to read
// offsets like call-site entries whose format nibble is all that matters.
static bool cur_encoded_value(struct eh_cursor *c, uint8_t format,
                              uint64_t *out)
{
    switch (format) {
    case DW_EH_PE_absptr:
    case DW_EH_PE_udata8:
    case DW_EH_PE_sdata8:
        return cur_bytes(c, out, 8);
    case DW_EH_PE_uleb128:
        return cur_uleb(c, out);
    case DW_EH_PE_udata2: {
        uint16_t v;
        if (!cur_bytes(c, &v, 2)) {
            return false;
        }
        *out = v;
        return true;
    }
    case DW_EH_PE_udata4: {
        uint32_t v;
        if (!cur_bytes(c, &v, 4)) {
            return false;
        }
        *out = v;
        return true;
    }
    case DW_EH_PE_sleb128: {
        int64_t v;
        if (!cur_sleb(c, &v)) {
            return false;
        }
        *out = (uint64_t)v;
        return true;
    }
    case DW_EH_PE_sdata2: {
        int16_t v;
        if (!cur_bytes(c, &v, 2)) {
            return false;
        }
        *out = (uint64_t)(int64_t)v;
        return true;
    }
    case DW_EH_PE_sdata4: {
        int32_t v;
        if (!cur_bytes(c, &v, 4)) {
            return false;
        }
        *out = (uint64_t)(int64_t)v;
        return true;
    }
    default:
        return false;
    }
}

// Read a fully encoded pointer, applying the pcrel base when present. A raw
// value of zero decodes to the NULL pointer per convention. Indirect
// encodings cannot be resolved statically and fail.
static bool cur_encoded(struct eh_cursor *c, uint8_t enc, uint64_t *out)
{
    if (enc == DW_EH_PE_omit || (enc & DW_EH_PE_indirect)) {
        return false;
    }
    uint64_t base_va = c->va;
    uint64_t raw;
    if (!cur_encoded_value(c, enc & 0x0F, &raw)) {
        return false;
    }
    if (raw == 0) {
        *out = 0;
        return true;
    }
    switch (enc & 0x70) {
    case 0x00:
        *out = raw;
        return true;
    case DW_EH_PE_pcrel:
        *out = base_va + raw;  // sdata formats wrap correctly
        return true;
    default:
        return false;
    }
}

// What an FDE needs from its CIE.
struct cie_info {
    uint64_t off;  // offset of the CIE within .eh_frame
    bool has_z;
    bool has_lsda;
    uint8_t lsda_enc;
    uint8_t fde_enc;
};

// Parse one LSDA (in .gcc_except_table) and record every landing pad that
// lands in an executable section. Landing pads default to being relative to
// the function start (@LPStart omitted). Returns false on malformed or
// unsupported data — the caller fails closed.
static bool collect_lsda_landing_pads(const uint8_t *file, size_t file_size,
                                      const Elf64_Ehdr *eh, uint64_t lsda_va,
                                      uint64_t func_va,
                                      const struct exec_range *exec,
                                      size_t num_exec, uint64_t **arr,
                                      size_t *n, size_t *cap, bool *oom)
{
    size_t avail;
    const uint8_t *p = va_to_file(file, file_size, eh, lsda_va, 1, &avail);
    if (p == NULL) {
        return false;
    }
    struct eh_cursor c = { p, p + avail, lsda_va };

    uint8_t lpstart_enc;
    if (!cur_u8(&c, &lpstart_enc)) {
        return false;
    }
    uint64_t lpstart = func_va;
    if (lpstart_enc != DW_EH_PE_omit &&
        !cur_encoded(&c, lpstart_enc, &lpstart)) {
        return false;
    }

    uint8_t ttype_enc;
    uint64_t ttype_off;
    if (!cur_u8(&c, &ttype_enc)) {
        return false;
    }
    if (ttype_enc != DW_EH_PE_omit && !cur_uleb(&c, &ttype_off)) {
        return false;
    }

    uint8_t cs_enc;
    uint64_t cs_len;
    if (!cur_u8(&c, &cs_enc) || (cs_enc & 0xF0) != 0 ||
        !cur_uleb(&c, &cs_len)) {
        return false;
    }
    if ((uint64_t)(c.end - c.p) < cs_len) {
        return false;
    }
    const uint8_t *cs_end = c.p + cs_len;
    while (c.p < cs_end) {
        uint64_t cs_start, cs_length, cs_lp, cs_action;
        if (!cur_encoded_value(&c, cs_enc, &cs_start) ||
            !cur_encoded_value(&c, cs_enc, &cs_length) ||
            !cur_encoded_value(&c, cs_enc, &cs_lp) ||
            !cur_uleb(&c, &cs_action)) {
            return false;
        }
        if (cs_lp != 0) {
            uint64_t target = lpstart + cs_lp;
            if (va_in_exec(exec, num_exec, target) &&
                !append_va(arr, n, cap, target)) {
                *oom = true;
                return false;
            }
        }
    }
    return true;
}

// Walk .eh_frame's CIEs and FDEs to find each function's LSDA and collect
// its exception landing pads: the unwinder transfers control to them, so
// they are branch targets no relocation or jump table mentions. Returns
// false on malformed or unsupported data — landing pads that cannot be
// enumerated make rewriting unsafe, so the caller must fail closed.
static bool collect_landing_pads(const uint8_t *file, size_t file_size,
                                 const Elf64_Ehdr *eh,
                                 const uint8_t *eh_frame, size_t eh_frame_len,
                                 uint64_t eh_frame_va,
                                 const struct exec_range *exec,
                                 size_t num_exec, uint64_t **arr, size_t *n,
                                 size_t *cap, size_t *num_pads, bool *oom)
{
    struct cie_info *cies = NULL;
    size_t num_cies = 0;
    size_t cies_cap = 0;
    struct eh_cursor c = { eh_frame, eh_frame + eh_frame_len, eh_frame_va };
    bool ok = false;

    while ((size_t)(c.end - c.p) >= 4) {
        uint64_t entry_off = (uint64_t)(c.p - eh_frame);
        uint32_t length;
        if (!cur_bytes(&c, &length, 4)) {
            goto out;
        }
        if (length == 0) {
            break;  // terminator
        }
        if (length == UINT32_MAX ||
            (uint64_t)(c.end - c.p) < length) {
            goto out;  // 64-bit records unsupported
        }
        struct eh_cursor entry = { c.p, c.p + length, c.va };
        c.p += length;
        c.va += length;

        uint64_t id_va = entry.va;
        uint32_t cie_id;
        if (!cur_bytes(&entry, &cie_id, 4)) {
            goto out;
        }
        if (cie_id == 0) {
            // CIE: recover the augmentation layout and pointer encodings.
            struct cie_info info = {
                .off = entry_off,
                .fde_enc = DW_EH_PE_absptr,
            };
            uint8_t version;
            if (!cur_u8(&entry, &version) ||
                (version != 1 && version != 3 && version != 4)) {
                goto out;
            }
            char aug[8];
            size_t aug_len = 0;
            for (;;) {
                uint8_t ch;
                if (!cur_u8(&entry, &ch) || aug_len >= sizeof(aug)) {
                    goto out;
                }
                aug[aug_len++] = (char)ch;
                if (ch == '\0') {
                    break;
                }
            }
            if (version == 4) {
                uint8_t address_size, segment_size;
                if (!cur_u8(&entry, &address_size) || address_size != 8 ||
                    !cur_u8(&entry, &segment_size) || segment_size != 0) {
                    goto out;
                }
            }
            uint64_t code_align;
            int64_t data_align;
            if (!cur_uleb(&entry, &code_align) ||
                !cur_sleb(&entry, &data_align)) {
                goto out;
            }
            uint64_t ret_reg;
            if (version == 1) {
                uint8_t r;
                if (!cur_u8(&entry, &r)) {
                    goto out;
                }
                ret_reg = r;
            } else if (!cur_uleb(&entry, &ret_reg)) {
                goto out;
            }
            if (aug[0] == 'z') {
                info.has_z = true;
                uint64_t aug_data_len;
                if (!cur_uleb(&entry, &aug_data_len)) {
                    goto out;
                }
                for (size_t i = 1; aug[i] != '\0'; i++) {
                    uint8_t penc;
                    uint64_t skip;
                    switch (aug[i]) {
                    case 'L':
                        info.has_lsda = true;
                        if (!cur_u8(&entry, &info.lsda_enc)) {
                            goto out;
                        }
                        break;
                    case 'P':
                        // Skip the personality routine pointer; indirect
                        // encodings are fine to skip by format size.
                        if (!cur_u8(&entry, &penc) ||
                            !cur_encoded_value(&entry, penc & 0x0F, &skip)) {
                            goto out;
                        }
                        break;
                    case 'R':
                        if (!cur_u8(&entry, &info.fde_enc)) {
                            goto out;
                        }
                        break;
                    case 'S':
                    case 'B':
                        break;  // no augmentation data
                    default:
                        goto out;  // unknown layout: fail closed
                    }
                }
            } else if (aug[0] != '\0') {
                goto out;  // pre-"z" augmentations unsupported
            }
            if (num_cies == cies_cap) {
                size_t new_cap = cies_cap == 0 ? 4 : cies_cap * 2;
                struct cie_info *q =
                    realloc(cies, new_cap * sizeof(*cies));
                if (q == NULL) {
                    *oom = true;
                    goto out;
                }
                cies = q;
                cies_cap = new_cap;
            }
            cies[num_cies++] = info;
        } else {
            // FDE: cie_id is the distance back from the id field to its CIE.
            uint64_t cie_off = entry_off + 4 - cie_id;
            const struct cie_info *info = NULL;
            for (size_t i = 0; i < num_cies; i++) {
                if (cies[i].off == cie_off) {
                    info = &cies[i];
                    break;
                }
            }
            if (info == NULL) {
                goto out;
            }
            (void)id_va;
            uint64_t pc_begin, pc_range;
            if (!cur_encoded(&entry, info->fde_enc, &pc_begin) ||
                !cur_encoded_value(&entry, info->fde_enc & 0x0F, &pc_range)) {
                goto out;
            }
            if (!info->has_z) {
                continue;  // no augmentation data, so no LSDA
            }
            uint64_t aug_data_len;
            if (!cur_uleb(&entry, &aug_data_len)) {
                goto out;
            }
            if (!info->has_lsda || aug_data_len == 0) {
                continue;
            }
            uint64_t lsda_va;
            if (!cur_encoded(&entry, info->lsda_enc, &lsda_va)) {
                goto out;
            }
            if (lsda_va == 0) {
                continue;
            }
            size_t before = *n;
            if (!collect_lsda_landing_pads(file, file_size, eh, lsda_va,
                                           pc_begin, exec, num_exec, arr, n,
                                           cap, oom)) {
                goto out;
            }
            *num_pads += *n - before;
        }
    }
    ok = true;
out:
    free(cies);
    return ok;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "peepopt optimizes x86-64 binaries, rewriting them in-place\n" \
            "usage: %s [--dry-run] [--stats] [--verbose] [-m|--march apx] <ELF_FILE>\n", program);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    uint32_t idx;
    int rewrites = 0;
    bool dry_run = false;
    bool stats = false;
    bool verbose = false;
    bool march_apx = false;
    static const struct option long_opts[] = {
        { "dry-run", no_argument,       0, 'd' },
        { "march",   required_argument, 0, 'm' },
        { "stats",   no_argument,       0, 's' },
        { "verbose", no_argument,       0, 'v' },
        { NULL,      0,                 0,  0  }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "vm:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd':
            dry_run = true;
            break;
        case 'm':
            // Comma-separated ISA extensions beyond the always-on
            // x86-64-v3 rewrites. Only APX exists today.
            for (char *tok = strtok(optarg, ","); tok != NULL;
                 tok = strtok(NULL, ",")) {
                if (strcmp(tok, "apx") == 0) {
                    march_apx = true;
                } else {
                    fprintf(stderr, "unknown -m feature: %s\n", tok);
                    usage(argv[0]);
                }
            }
            break;
        case 's':
            stats = true;
            break;
        case 'v':
            verbose = true;
            break;
        default:
            usage(argv[0]);
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
    }

    peepopt_set_verbose(verbose);

    int fd = open(argv[optind], dry_run ? O_RDONLY : O_RDWR);
    if (fd == -1) {
        perror("Error opening file");
        exit(1);
    }

    xed_tables_init();
    xed_set_verbosity(99);
    xed_set_log_file(stderr);

    struct stat statbuf;
    int err = fstat(fd, &statbuf);
    if (err != 0) {
        fprintf(stderr, "failed to stat file: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    const size_t file_size = statbuf.st_size;
    void *addr = mmap(/*addr=*/ NULL, /*length=*/ file_size, PROT_READ | (dry_run ? 0 : PROT_WRITE), MAP_SHARED, fd, /*offset=*/ 0);
    if (addr == MAP_FAILED) {
        fprintf(stderr, "failed to mmap file: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    if (file_size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "file too small to be an ELF64 binary\n");
        munmap(addr, file_size);
        close(fd);
        return 1;
    }

    // read ELF header, first thing in the file
    const Elf64_Ehdr *elf_header = addr;
    if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0 ||
        elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "not a valid ELF64 file\n");
        munmap(addr, file_size);
        close(fd);
        return 1;
    }

    // The decoder and rewriter assume x86-64. Decoding another architecture's
    // executable sections as x86-64 and rewriting them in place would corrupt
    // the file, so refuse anything that is not EM_X86_64.
    if (elf_header->e_machine != EM_X86_64) {
        fprintf(stderr, "not an x86-64 ELF file (e_machine=%u); refusing to rewrite\n",
                (unsigned)elf_header->e_machine);
        munmap(addr, file_size);
        close(fd);
        return 1;
    }

    if (elf_header->e_shentsize < sizeof(Elf64_Shdr) ||
        elf_header->e_shoff > file_size ||
        (uint64_t)elf_header->e_shnum * elf_header->e_shentsize > file_size - elf_header->e_shoff ||
        elf_header->e_shstrndx >= elf_header->e_shnum) {
        fprintf(stderr, "malformed ELF section header table\n");
        munmap(addr, file_size);
        close(fd);
        return 1;
    }

    const Elf64_Shdr *section_header = (const Elf64_Shdr *)((const uint8_t *)addr + elf_header->e_shoff + (uint64_t)elf_header->e_shstrndx * elf_header->e_shentsize);

    // next, read the section, string data
    if (section_header->sh_offset > file_size ||
        section_header->sh_size > file_size - section_header->sh_offset) {
        fprintf(stderr, "malformed ELF section name string table\n");
        munmap(addr, file_size);
        close(fd);
        return 1;
    }
    const char *section_names = (const char *)addr + section_header->sh_offset;
    const size_t section_names_size = section_header->sh_size;

    const uint8_t *file = addr;

    // Discovery pass: find read-only data sections that may hold jump tables
    // and the executable VA ranges that relocated code pointers must land in.
    struct peepopt_data_section data_sections[4];
    size_t num_data_sections = 0;
    struct exec_range exec_ranges[16];
    size_t num_exec_ranges = 0;
    const uint8_t *eh_frame = NULL;
    size_t eh_frame_len = 0;
    uint64_t eh_frame_va = 0;
    for (idx = 0; idx < elf_header->e_shnum; ++idx) {
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(file + elf_header->e_shoff + (uint64_t)idx * elf_header->e_shentsize);
        if (sh->sh_offset > file_size ||
            sh->sh_size > file_size - sh->sh_offset ||
            sh->sh_name >= section_names_size) {
            continue;
        }
        const char *name = section_names + sh->sh_name;
        if (memchr(name, '\0', section_names_size - sh->sh_name) == NULL) {
            continue;
        }
        if ((sh->sh_flags & SHF_EXECINSTR) &&
            num_exec_ranges < sizeof(exec_ranges) / sizeof(exec_ranges[0])) {
            exec_ranges[num_exec_ranges].lo = sh->sh_addr;
            exec_ranges[num_exec_ranges].hi = sh->sh_addr + sh->sh_size;
            ++num_exec_ranges;
        }
        if (sh->sh_type != SHT_NOBITS &&
            num_data_sections < sizeof(data_sections) / sizeof(data_sections[0]) &&
            (strcmp(name, ".rodata") == 0 ||
             strcmp(name, ".data.rel.ro") == 0)) {
            data_sections[num_data_sections].bytes = file + sh->sh_offset;
            data_sections[num_data_sections].vaddr = sh->sh_addr;
            data_sections[num_data_sections].size = sh->sh_size;
            ++num_data_sections;
        }
        if (sh->sh_type != SHT_NOBITS && strcmp(name, ".eh_frame") == 0) {
            eh_frame = file + sh->sh_offset;
            eh_frame_len = sh->sh_size;
            eh_frame_va = sh->sh_addr;
        }
    }

    // Relocation pass: collect code pointers installed by the dynamic linker
    // (vtables, function pointers, computed-goto labels). RELATIVE/IRELATIVE
    // RELA entries carry the target in the addend; RELR entries name slots
    // whose in-place value is the link-time target.
    uint64_t *extra_targets = NULL;
    size_t num_extra_targets = 0;
    size_t reloc_cap = 0;
    bool reloc_oom = false;
    for (idx = 0; idx < elf_header->e_shnum && !reloc_oom; ++idx) {
        const Elf64_Shdr *sh = (const Elf64_Shdr *)(file + elf_header->e_shoff + (uint64_t)idx * elf_header->e_shentsize);
        if (sh->sh_offset > file_size ||
            sh->sh_size > file_size - sh->sh_offset) {
            continue;
        }
        if (sh->sh_type == SHT_RELA) {
            size_t count = sh->sh_size / sizeof(Elf64_Rela);
            const Elf64_Rela *rela = (const Elf64_Rela *)(file + sh->sh_offset);
            for (size_t i = 0; i < count && !reloc_oom; ++i) {
                uint32_t type = ELF64_R_TYPE(rela[i].r_info);
                if (type != R_X86_64_RELATIVE && type != R_X86_64_IRELATIVE) {
                    continue;
                }
                uint64_t va = (uint64_t)rela[i].r_addend;
                if (va_in_exec(exec_ranges, num_exec_ranges, va)) {
                    reloc_oom = !append_va(&extra_targets, &num_extra_targets,
                                           &reloc_cap, va);
                }
            }
        } else if (sh->sh_type == SHT_RELR) {
            // Decode the packed format: an even entry is the address of the
            // next relocated slot; an odd entry is a bitmap of 63 slots
            // following the previous run.
            size_t count = sh->sh_size / sizeof(uint64_t);
            const uint64_t *relr = (const uint64_t *)(file + sh->sh_offset);
            uint64_t where = 0;
            for (size_t i = 0; i < count && !reloc_oom; ++i) {
                uint64_t entry = relr[i];
                if ((entry & 1) == 0) {
                    reloc_oom = !add_relr_slot(file, file_size, elf_header,
                                               exec_ranges, num_exec_ranges,
                                               entry, &extra_targets,
                                               &num_extra_targets, &reloc_cap);
                    where = entry + sizeof(uint64_t);
                } else {
                    for (int bit = 0; (entry >>= 1) != 0 && !reloc_oom;
                         ++bit) {
                        if (entry & 1) {
                            reloc_oom = !add_relr_slot(
                                    file, file_size, elf_header,
                                    exec_ranges, num_exec_ranges,
                                    where + (uint64_t)bit * sizeof(uint64_t),
                                    &extra_targets, &num_extra_targets,
                                    &reloc_cap);
                        }
                    }
                    where += 63 * sizeof(uint64_t);
                }
            }
        }
    }
    if (reloc_oom) {
        fprintf(stderr, "out of memory collecting relocation targets\n");
        free(extra_targets);
        munmap(addr, file_size);
        close(fd);
        return 1;
    }
    size_t num_relocs = num_extra_targets;

    // Landing-pad pass: the unwinder branches to exception landing pads, so
    // they must be protected like any other branch target. Landing pads
    // that cannot be enumerated would make every rewrite in their function
    // unsafe, so a malformed or unsupported .eh_frame is a hard error.
    size_t num_landing_pads = 0;
    if (eh_frame != NULL) {
        bool eh_oom = false;
        if (!collect_landing_pads(file, file_size, elf_header, eh_frame,
                                  eh_frame_len, eh_frame_va, exec_ranges,
                                  num_exec_ranges, &extra_targets,
                                  &num_extra_targets, &reloc_cap,
                                  &num_landing_pads, &eh_oom)) {
            fprintf(stderr, eh_oom
                    ? "out of memory collecting landing pads\n"
                    : "cannot parse .eh_frame/.gcc_except_table; exception "
                      "landing pads would be unprotected, refusing to "
                      "rewrite\n");
            free(extra_targets);
            munmap(addr, file_size);
            close(fd);
            return 1;
        }
    }
    if (verbose) {
        printf("collected %zu data sections, %zu relocation code pointers, "
               "%zu exception landing pads\n",
               num_data_sections, num_relocs, num_landing_pads);
    }

    // read all section headers
    for (idx = 0; idx < elf_header->e_shnum; ++idx) {
        section_header = (const Elf64_Shdr *)((const uint8_t *)addr + elf_header->e_shoff + (uint64_t)idx * elf_header->e_shentsize);
        if (!(section_header->sh_flags & SHF_EXECINSTR)) {
            continue;
        }

        if (section_header->sh_name >= section_names_size) {
            fprintf(stderr, "section %u has out-of-bounds name offset\n", idx);
            continue;
        }
        const char *name = section_names + section_header->sh_name;
        if (memchr(name, '\0', section_names_size - section_header->sh_name) == NULL) {
            fprintf(stderr, "section %u name is not NUL-terminated\n", idx);
            continue;
        }
        if (verbose) {
            printf("name: %s\n", name);
        }
        if (strcmp(name, ".text") != 0) {
            continue;
        }

        if (section_header->sh_offset > file_size ||
            section_header->sh_size > file_size - section_header->sh_offset) {
            fprintf(stderr, "section %u has out-of-bounds data\n", idx);
            continue;
        }
        uint8_t *buf = (uint8_t *)addr + section_header->sh_offset;
        struct peepopt_ctx ctx = {
            .text_vaddr = section_header->sh_addr,
            .data_sections = data_sections,
            .num_data_sections = num_data_sections,
            .extra_targets = extra_targets,
            .num_extra_targets = num_extra_targets,
        };
        int section_rewrites = check_shifts(buf, section_header->sh_size, /*replace=*/ !dry_run, &ctx);
        if (section_rewrites < 0) {
            fprintf(stderr, "check_shifts failed on section %u\n", idx);
            free(extra_targets);
            munmap(addr, file_size);
            close(fd);
            return 1;
        }
        rewrites += section_rewrites;
        int andn_rewrites = check_andn(buf, section_header->sh_size, /*replace=*/ !dry_run, &ctx);
        if (andn_rewrites < 0) {
            fprintf(stderr, "check_andn failed on section %u\n", idx);
            free(extra_targets);
            munmap(addr, file_size);
            close(fd);
            return 1;
        }
        rewrites += andn_rewrites;
        int vex3_rewrites = check_vex3(buf, section_header->sh_size, /*replace=*/ !dry_run, &ctx);
        if (vex3_rewrites < 0) {
            fprintf(stderr, "check_vex3 failed on section %u\n", idx);
            free(extra_targets);
            munmap(addr, file_size);
            close(fd);
            return 1;
        }
        rewrites += vex3_rewrites;
        if (march_apx) {
            int apx_rewrites = check_apx(buf, section_header->sh_size, /*replace=*/ !dry_run, &ctx);
            if (apx_rewrites < 0) {
                fprintf(stderr, "check_apx failed on section %u\n", idx);
                free(extra_targets);
                munmap(addr, file_size);
                close(fd);
                return 1;
            }
            rewrites += apx_rewrites;
        }
    }
    free(extra_targets);

    if (stats) {
        peepopt_print_stats();
    }
    printf("%d rewrites\n", rewrites);

    munmap(addr, file_size);
    close(fd);
    return 0;
}

