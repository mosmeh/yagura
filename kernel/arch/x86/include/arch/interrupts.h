#pragma once

#include <kernel/api/x86/asm/processor-flags.h>
#include <stdbool.h>

#define IRQ(i) (0x20 + (i))

static inline bool __interrupts_enabled(void) {
    unsigned long flags;
    __asm__ volatile("pushf\n"
                     "pop %0\n"
                     : "=r"(flags));
    return flags & X86_EFLAGS_IF;
}

static inline void __enable_interrupts(void) { __asm__ volatile("sti"); }

static inline void __disable_interrupts(void) { __asm__ volatile("cli"); }

static inline void __wait_for_interrupt(void) { __asm__ volatile("hlt"); }

#define arch_interrupts_enabled __interrupts_enabled
#define arch_enable_interrupts __enable_interrupts
#define arch_disable_interrupts __disable_interrupts
#define arch_wait_for_interrupt __wait_for_interrupt
