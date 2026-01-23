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
        printf("failed to stat file: %s\n", strerror(errno));
        return 1;
    }

    void *addr = mmap(/*addr=*/ NULL, /*length=*/ statbuf.st_size, PROT_READ | (dry_run ? 0 : PROT_WRITE), MAP_SHARED, fd, /*offset=*/ 0);
    if (addr == NULL) {
        printf("failed to mmap file: %d\n", errno);
        return 1;
    }

    // read ELF header, first thing in the file
    const Elf64_Ehdr *elf_header = addr;
    const Elf64_Shdr *section_header = addr + elf_header->e_shoff + elf_header->e_shstrndx * sizeof(*section_header);

    // next, read the section, string data
    const char *section_names = addr + section_header->sh_offset;

    // read all section headers
    for (idx = 0; idx < elf_header->e_shnum; ++idx) {
        section_header = addr + elf_header->e_shoff + idx * sizeof(*section_header);
        if (!(section_header->sh_flags & SHF_EXECINSTR)) {
            continue;
        }

        const char *name = section_names + section_header->sh_name;
        printf("name: %s\n", name);
        if (strcmp(name, ".text") != 0) {
            continue;
        }

        uint8_t *buf = addr + section_header->sh_offset;
        rewrites += check_shifts(buf, section_header->sh_size, /*replace=*/ !dry_run);
    }

    printf("%d rewrites\n", rewrites);

    return 0;
}

