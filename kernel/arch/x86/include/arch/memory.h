#pragma once

#ifndef __ASSEMBLER__

#include <common/stdint.h>
#include <kernel/arch/x86/ctrl_regs.h>

static inline void __invalidate_tlb_page(uintptr_t virt_addr) {
    __asm__ volatile("invlpg (%0)" ::"r"(virt_addr) : "memory");
}

static inline void __full_memory_barrier(void) {
    __asm__ volatile("mfence" ::: "memory");
}

#define arch_invalidate_tlb_page __invalidate_tlb_page
#define arch_full_memory_barrier __full_memory_barrier

#endif
