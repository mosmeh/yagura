#pragma once

#include <stdint.h>

typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;
typedef uint32_t Elf32_Word;
typedef uint16_t Elf32_Half;

#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6
#define EI_OSABI 7
#define EI_ABIVERSION 8
#define EI_NIDENT 16

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

#define ELFCLASS32 1
#define ELFDATA2LSB 1

#define ELFOSABI_NONE 0             // UNIX System V ABI
#define ELFOSABI_SYSV ELFOSABI_NONE // Alias.
#define ELFOSABI_GNU 3              // Object uses GNU ELF extensions.
#define ELFOSABI_LINUX ELFOSABI_GNU // Compatibility alias.

#define IS_ELF(ehdr)                                                           \
    ((ehdr).e_ident[EI_MAG0] == ELFMAG0 &&                                     \
     (ehdr).e_ident[EI_MAG1] == ELFMAG1 &&                                     \
     (ehdr).e_ident[EI_MAG2] == ELFMAG2 && (ehdr).e_ident[EI_MAG3] == ELFMAG3)

#define ET_EXEC 2
#define EM_386 3
#define EV_CURRENT 1

typedef struct elfhdr {
    unsigned char e_ident[EI_NIDENT];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
} Elf32_Phdr;

#define PT_NULL 0 // Program header table entry unused
#define PT_LOAD 1 // Loadable program segment
#define PT_TLS 7  // Thread-local storage segment

#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

typedef struct {
    uint32_t a_type;
    union {
        uint32_t a_val;
    } a_un;
} Elf32_auxv_t;

#define AT_NULL 0    // End of vector
#define AT_IGNORE 1  // Entry should be ignored
#define AT_PHDR 3    // Program headers for program
#define AT_PHENT 4   // Size of program header entry
#define AT_PHNUM 5   // Number of program headers
#define AT_PAGESZ 6  // System page size
#define AT_ENTRY 9   // Entry point of program
#define AT_UID 11    // Real uid
#define AT_EUID 12   // Effective uid
#define AT_GID 13    // Real gid
#define AT_EGID 14   // Effective gid
#define AT_HWCAP 16  // Machine-dependent hints about processor capabilities.
#define AT_CLKTCK 17 // Frequency of times()
#define AT_SECURE 23 // Boolean, was exec setuid-like?
#define AT_RANDOM 25 // Address of 16 random bytes.
#define AT_EXECFN 31 // Filename of executable.
