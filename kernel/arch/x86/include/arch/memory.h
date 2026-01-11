#pragma once

#ifndef __ASSEMBLER__

#include <kernel/arch/x86/ctrl_regs.h>
#include <stdint.h>

static inline void __flush_tlb_all(void) { write_cr3(read_cr3()); }

static inline void __flush_tlb_single(uintptr_t virt_addr) {
    __asm__ volatile("invlpg (%0)" ::"r"(virt_addr) : "memory");
}

static inline void __full_memory_barrier(void) {
    __asm__ volatile("mfence" ::: "memory");
}

#define arch_flush_tlb_all __flush_tlb_all
#define arch_flush_tlb_single __flush_tlb_single
#define arch_full_memory_barrier __full_memory_barrier

#endif
