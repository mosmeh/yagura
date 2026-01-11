#pragma once

#include <kernel/api/elf.h>

#define ELF_CLASS ELFCLASS32
#define ELF_DATA ELFDATA2LSB
#define ELF_ARCH EM_386

typedef Elf32_Ehdr elf_ehdr_t;
typedef Elf32_Phdr elf_phdr_t;
typedef Elf32_auxv_t elf_auxv_t;

#define ELF_ET_DYN_BASE 0x400000
