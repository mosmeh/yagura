#pragma once

#define NUM_GDT_ENTRIES 6
#define KERNEL_CS 0x08
#define KERNEL_DS 0x10
#define USER_CS 0x18
#define USER_DS 0x20
#define TSS_SELECTOR 0x28

#ifndef ASM_FILE

#include <stdint.h>

struct gdt_segment {
    uint16_t limit_lo : 16;
    uint16_t base_lo : 16;
    uint8_t base_mid : 8;
    uint8_t access : 8;
    uint8_t limit_hi : 4;
    uint8_t flags : 4;
    uint8_t base_hi : 8;
} __attribute__((packed));

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
} __attribute__((packed));

void gdt_init_cpu(void);
void gdt_set_cpu_kernel_stack(uintptr_t stack_top);

#endif
