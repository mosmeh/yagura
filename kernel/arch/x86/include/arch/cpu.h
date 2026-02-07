#pragma once

#include <common/limits.h>
#include <common/macros.h>
#include <kernel/arch/interrupts.h>
#include <kernel/arch/x86/cpu.h>
#include <kernel/arch/x86/gdt.h>

struct arch_cpu {
    uint32_t family;
    uint32_t model;
    uint32_t stepping;
    unsigned long features[NUM_X86_FEATURES / LONG_WIDTH + 1];
    uint8_t apic_id;
    uint8_t phys_addr_bits;
    uint8_t virt_addr_bits;
    // ebx, ecx, edx + '\0'
    char vendor_id[3UL * sizeof(uint32_t) + 1];
    // 3 * (eax, ebx, ecx, edx) + '\0'
    char model_name[3UL * 4 * sizeof(uint32_t) + 1];

    struct gdt_segment gdt[NUM_GDT_ENTRIES];
    struct tss tss;
    struct gdtr gdtr;
};

#ifdef ARCH_I386
#define __CPU_SEGMENT fs
#endif
#ifdef ARCH_X86_64
#define __CPU_SEGMENT gs
#endif

static inline unsigned long __cpu_read(size_t offset) {
    unsigned long value;
    __asm__ volatile("mov %%" STRINGIFY(__CPU_SEGMENT) ":%a[offset], %[value]"
                     : [value] "=r"(value)
                     : [offset] "ri"(offset));
    return value;
}

static inline void __cpu_relax(void) { __asm__ volatile("pause"); }

static inline void __cpu_halt(void) {
    arch_disable_interrupts();
    for (;;)
        arch_wait_for_interrupt();
}

#define arch_cpu_read __cpu_read
#define arch_cpu_relax __cpu_relax
#define arch_cpu_halt __cpu_halt
