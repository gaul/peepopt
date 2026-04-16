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

static void usage(const char *program)
{
    fprintf(stderr,
            "peepopt optimizes x86-64 binaries, rewriting them in-place\n" \
            "usage: %s [--dry-run] [--verbose] <ELF_FILE>\n", program);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    uint32_t idx;
    int rewrites = 0;
    bool dry_run = false;
    bool verbose = false;  // TODO:
    static const struct option long_opts[] = {
        { "dry-run", no_argument,       0, 'd' },
        { "verbose", no_argument,       0, 'v' },
        { NULL,      0,                 0,  0  }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "vq", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd':
            dry_run = true;
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
        printf("name: %s\n", name);
        if (strcmp(name, ".text") != 0) {
            continue;
        }

        if (section_header->sh_offset > file_size ||
            section_header->sh_size > file_size - section_header->sh_offset) {
            fprintf(stderr, "section %u has out-of-bounds data\n", idx);
            continue;
        }
        uint8_t *buf = (uint8_t *)addr + section_header->sh_offset;
        int section_rewrites = check_shifts(buf, section_header->sh_size, /*replace=*/ !dry_run);
        if (section_rewrites < 0) {
            fprintf(stderr, "check_shifts failed on section %u\n", idx);
            munmap(addr, file_size);
            close(fd);
            return 1;
        }
        rewrites += section_rewrites;
    }

    printf("%d rewrites\n", rewrites);

    munmap(addr, file_size);
    close(fd);
    return 0;
}

