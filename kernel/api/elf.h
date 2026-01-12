#pragma once

#include <common/stdint.h>

typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;

typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;

typedef uint32_t Elf32_Word;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Xword;

typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;

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

#define ELFCLASS32 1 // 32-bit objects
#define ELFCLASS64 2 // 64-bit objects
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
#define ET_DYN 3

#define EM_386 3     // Intel 80386
#define EM_X86_64 62 // AMD x86-64 architecture
#define EV_CURRENT 1

typedef struct {
    unsigned char e_ident[EI_NIDENT]; // Magic number and other info
    Elf32_Half e_type;                // Object file type
    Elf32_Half e_machine;             // Architecture
    Elf32_Word e_version;             // Object file version
    Elf32_Addr e_entry;               // Entry point virtual address
    Elf32_Off e_phoff;                // Program header table file offset
    Elf32_Off e_shoff;                // Section header table file offset
    Elf32_Word e_flags;               // Processor-specific flags
    Elf32_Half e_ehsize;              // ELF header size in bytes
    Elf32_Half e_phentsize;           // Program header table entry size
    Elf32_Half e_phnum;               // Program header table entry count
    Elf32_Half e_shentsize;           // Section header table entry size
    Elf32_Half e_shnum;               // Section header table entry count
    Elf32_Half e_shstrndx;            // Section header string table index
} Elf32_Ehdr;

typedef struct {
    unsigned char e_ident[EI_NIDENT]; // Magic number and other info
    Elf64_Half e_type;                // Object file type
    Elf64_Half e_machine;             // Architecture
    Elf64_Word e_version;             // Object file version
    Elf64_Addr e_entry;               // Entry point virtual address
    Elf64_Off e_phoff;                // Program header table file offset
    Elf64_Off e_shoff;                // Section header table file offset
    Elf64_Word e_flags;               // Processor-specific flags
    Elf64_Half e_ehsize;              // ELF header size in bytes
    Elf64_Half e_phentsize;           // Program header table entry size
    Elf64_Half e_phnum;               // Program header table entry count
    Elf64_Half e_shentsize;           // Section header table entry size
    Elf64_Half e_shnum;               // Section header table entry count
    Elf64_Half e_shstrndx;            // Section header string table index
} Elf64_Ehdr;

typedef struct {
    Elf32_Word p_type;   // Segment type
    Elf32_Off p_offset;  // Segment file offset
    Elf32_Addr p_vaddr;  // Segment virtual address
    Elf32_Addr p_paddr;  // Segment physical address
    Elf32_Word p_filesz; // Segment size in file
    Elf32_Word p_memsz;  // Segment size in memory
    Elf32_Word p_flags;  // Segment flags
    Elf32_Word p_align;  // Segment alignment
} Elf32_Phdr;

typedef struct {
    Elf64_Word p_type;    // Segment type
    Elf64_Word p_flags;   // Segment flags
    Elf64_Off p_offset;   // Segment file offset
    Elf64_Addr p_vaddr;   // Segment virtual address
    Elf64_Addr p_paddr;   // Segment physical address
    Elf64_Xword p_filesz; // Segment size in file
    Elf64_Xword p_memsz;  // Segment size in memory
    Elf64_Xword p_align;  // Segment alignment
} Elf64_Phdr;

#define PT_NULL 0   // Program header table entry unused
#define PT_LOAD 1   // Loadable program segment
#define PT_INTERP 3 // Program interpreter
#define PT_TLS 7    // Thread-local storage segment

#define PF_X 0x1 // Segment is executable
#define PF_W 0x2 // Segment is writable
#define PF_R 0x4 // Segment is readable

typedef struct {
    uint32_t a_type; // Entry type
    union {
        uint32_t a_val; // Integer value
    } a_un;
} Elf32_auxv_t;

typedef struct {
    uint64_t a_type; // Entry type
    union {
        uint64_t a_val; // Integer value
    } a_un;
} Elf64_auxv_t;

#define AT_NULL 0    // End of vector
#define AT_IGNORE 1  // Entry should be ignored
#define AT_PHDR 3    // Program headers for program
#define AT_PHENT 4   // Size of program header entry
#define AT_PHNUM 5   // Number of program headers
#define AT_PAGESZ 6  // System page size
#define AT_BASE 7    // base address of interpreter
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
