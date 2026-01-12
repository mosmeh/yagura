#pragma once

#include <kernel/api/elf.h>

#define ELF_DATA ELFDATA2LSB

#ifdef ARCH_I386
#define ELF_CLASS ELFCLASS32
#define ELF_ARCH EM_386

typedef Elf32_Ehdr elf_ehdr_t;
typedef Elf32_Phdr elf_phdr_t;
typedef Elf32_auxv_t elf_auxv_t;
#endif

#ifdef ARCH_X86_64
#define ELF_CLASS ELFCLASS64
#define ELF_ARCH EM_X86_64

typedef Elf64_Ehdr elf_ehdr_t;
typedef Elf64_Phdr elf_phdr_t;
typedef Elf64_auxv_t elf_auxv_t;
#endif

#define ELF_ET_DYN_BASE 0x400000
