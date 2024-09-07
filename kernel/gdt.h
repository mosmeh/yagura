#pragma once

#define NUM_GDT_ENTRIES 9
#define GDT_ENTRY_KERNEL_CS 1
#define GDT_ENTRY_KERNEL_DS 2
#define GDT_ENTRY_USER_CS 3
#define GDT_ENTRY_USER_DS 4
#define GDT_ENTRY_TSS 5
#define GDT_ENTRY_TLS_MIN 6
#define NUM_GDT_TLS_ENTRIES 3

#define KERNEL_CS (GDT_ENTRY_KERNEL_CS * 8)
#define KERNEL_DS (GDT_ENTRY_KERNEL_DS * 8)
#define USER_CS (GDT_ENTRY_USER_CS * 8)
#define USER_DS (GDT_ENTRY_USER_DS * 8)
#define TSS_SELECTOR (GDT_ENTRY_TSS * 8)

#ifndef ASM_FILE

#include <stdint.h>

struct gdt_segment {
    uint16_t limit_lo;
    uint16_t base_lo;
    uint8_t base_mid;
    union {
        uint8_t access;
        struct {
            uint8_t type : 4;
            uint8_t s : 1;
            uint8_t dpl : 2;
            uint8_t p : 1;
        };
    };
    union {
        struct {
            uint8_t limit_hi : 4;
            uint8_t flags : 4;
        };
        struct {
            uint8_t pad : 4;
            uint8_t avl : 1;
            uint8_t l : 1;
            uint8_t db : 1;
            uint8_t g : 1;
        };
    };
    uint8_t base_hi;
};

struct gdtr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

struct tss {
    uint32_t prev_tss;
    uint32_t esp0, ss0, esp1, ss1, esp2, ss2;
    uint32_t cr3;
    uint32_t eip, eflags, eax, ecx, edx, ebx, esp, ebp, esi, edi;
    uint32_t es, cs, ss, ds, fs, gs;
    uint32_t ldt;
    uint16_t trap, iomap_base;
};

void gdt_init_cpu(void);
void gdt_set_cpu_kernel_stack(uintptr_t stack_top);

#endif
