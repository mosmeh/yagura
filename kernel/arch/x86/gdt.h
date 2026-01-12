#pragma once

#ifdef ARCH_I386
#define NUM_GDT_ENTRIES 10
#define GDT_ENTRY_KERNEL_CS 1
#define GDT_ENTRY_KERNEL_DS 2
#define GDT_ENTRY_USER_CS 3
#define GDT_ENTRY_USER_DS 4
#define GDT_ENTRY_TSS 5
#define GDT_ENTRY_TLS_MIN 6
#define NUM_GDT_TLS_ENTRIES 3
#define GDT_ENTRY_CPU_ID 9
#endif

#ifdef ARCH_X86_64
#define NUM_GDT_ENTRIES 11
#define GDT_ENTRY_KERNEL_CS 1
#define GDT_ENTRY_KERNEL_DS 2
#define GDT_ENTRY_USER_DS 3
#define GDT_ENTRY_USER_CS 4
#define GDT_ENTRY_TSS 5
#define GDT_ENTRY_TSS2 6
#define GDT_ENTRY_TLS_MIN 7
#define NUM_GDT_TLS_ENTRIES 3
#define GDT_ENTRY_CPU_ID 10
#endif

#define KERNEL_CS (GDT_ENTRY_KERNEL_CS * 8)
#define KERNEL_DS (GDT_ENTRY_KERNEL_DS * 8)
#define USER_CS (GDT_ENTRY_USER_CS * 8)
#define USER_DS (GDT_ENTRY_USER_DS * 8)
#define TSS_SELECTOR (GDT_ENTRY_TSS * 8)
#ifdef ARCH_X86_64
#define TSS_SELECTOR2 (GDT_ENTRY_TSS2 * 8)
#endif
#define CPU_ID_SELECTOR (GDT_ENTRY_CPU_ID * 8)

#ifndef __ASSEMBLER__

#include <common/stdint.h>

struct gdt_segment {
    union {
        struct {
            uint16_t limit_lo;
            uint16_t base_lo;
            uint8_t base_mid;
            uint8_t type : 4;
            uint8_t descriptor_type : 1;
            uint8_t dpl : 2;
            uint8_t segment_present : 1;

            uint8_t limit_hi : 4;
            uint8_t avl : 1;
            uint8_t operation_size64 : 1;
            uint8_t operation_size32 : 1;
            uint8_t granularity : 1;
            uint8_t base_hi;
        };
        struct {
            uint32_t low;
            uint32_t high;
        };
    };
};

struct gdtr {
    uint16_t limit;
#ifdef ARCH_I386
    uint32_t base;
#endif
#ifdef ARCH_X86_64
    uint64_t base;
#endif
} __attribute__((packed));

struct tss {
#ifdef ARCH_I386
    uint32_t prev_tss;
    uint32_t esp0, ss0, esp1, ss1, esp2, ss2;
    uint32_t cr3;
    uint32_t eip, eflags, eax, ecx, edx, ebx, esp, ebp, esi, edi;
    uint32_t es, cs, ss, ds, fs, gs;
    uint32_t ldt;
    uint16_t trap, iomap_base;
#endif
#ifdef ARCH_X86_64
    uint32_t __1;
    uint32_t rsp0l;
    uint32_t rsp0h;
    uint32_t rsp1l;
    uint32_t rsp1h;
    uint32_t rsp2l;
    uint32_t rsp2h;
    uint64_t __2;
    uint32_t ist1l;
    uint32_t ist1h;
    uint32_t ist2l;
    uint32_t ist2h;
    uint32_t ist3l;
    uint32_t ist3h;
    uint32_t ist4l;
    uint32_t ist4h;
    uint32_t ist5l;
    uint32_t ist5h;
    uint32_t ist6l;
    uint32_t ist6h;
    uint32_t ist7l;
    uint32_t ist7h;
    uint64_t __3;
    uint16_t __4;
    uint16_t iomap_base;
#endif
} __attribute__((packed));

void gdt_init_cpu(void);

#endif
