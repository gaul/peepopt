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
static const uint8_t *va_to_file(const uint8_t *file, size_t file_size,
                                 const Elf64_Ehdr *eh, uint64_t va,
                                 size_t need)
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
                                  sizeof(uint64_t));
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
    }

    // Relocation pass: collect code pointers installed by the dynamic linker
    // (vtables, function pointers, computed-goto labels). RELATIVE/IRELATIVE
    // RELA entries carry the target in the addend; RELR entries name slots
    // whose in-place value is the link-time target.
    uint64_t *reloc_targets = NULL;
    size_t num_reloc_targets = 0;
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
                    reloc_oom = !append_va(&reloc_targets, &num_reloc_targets,
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
                                               entry, &reloc_targets,
                                               &num_reloc_targets, &reloc_cap);
                    where = entry + sizeof(uint64_t);
                } else {
                    for (int bit = 0; (entry >>= 1) != 0 && !reloc_oom;
                         ++bit) {
                        if (entry & 1) {
                            reloc_oom = !add_relr_slot(
                                    file, file_size, elf_header,
                                    exec_ranges, num_exec_ranges,
                                    where + (uint64_t)bit * sizeof(uint64_t),
                                    &reloc_targets, &num_reloc_targets,
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
        free(reloc_targets);
        munmap(addr, file_size);
        close(fd);
        return 1;
    }
    if (verbose) {
        printf("collected %zu data sections, %zu relocation code pointers\n",
               num_data_sections, num_reloc_targets);
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
            .reloc_targets = reloc_targets,
            .num_reloc_targets = num_reloc_targets,
        };
        int section_rewrites = check_shifts(buf, section_header->sh_size, /*replace=*/ !dry_run, &ctx);
        if (section_rewrites < 0) {
            fprintf(stderr, "check_shifts failed on section %u\n", idx);
            free(reloc_targets);
            munmap(addr, file_size);
            close(fd);
            return 1;
        }
        rewrites += section_rewrites;
        int andn_rewrites = check_andn(buf, section_header->sh_size, /*replace=*/ !dry_run, &ctx);
        if (andn_rewrites < 0) {
            fprintf(stderr, "check_andn failed on section %u\n", idx);
            free(reloc_targets);
            munmap(addr, file_size);
            close(fd);
            return 1;
        }
        rewrites += andn_rewrites;
        int vex3_rewrites = check_vex3(buf, section_header->sh_size, /*replace=*/ !dry_run, &ctx);
        if (vex3_rewrites < 0) {
            fprintf(stderr, "check_vex3 failed on section %u\n", idx);
            free(reloc_targets);
            munmap(addr, file_size);
            close(fd);
            return 1;
        }
        rewrites += vex3_rewrites;
        if (march_apx) {
            int apx_rewrites = check_apx(buf, section_header->sh_size, /*replace=*/ !dry_run, &ctx);
            if (apx_rewrites < 0) {
                fprintf(stderr, "check_apx failed on section %u\n", idx);
                free(reloc_targets);
                munmap(addr, file_size);
                close(fd);
                return 1;
            }
            rewrites += apx_rewrites;
        }
    }
    free(reloc_targets);

    if (stats) {
        peepopt_print_stats();
    }
    printf("%d rewrites\n", rewrites);

    munmap(addr, file_size);
    close(fd);
    return 0;
}

