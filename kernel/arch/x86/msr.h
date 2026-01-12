#pragma once

#define MSR_EFER 0xc0000080
#define MSR_IA32_CR_PAT 0x00000277

#define EFER_LME 0x100

#ifndef __ASSEMBLER__

#include <common/stdint.h>

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t lo;
    uint32_t hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr(uint32_t msr, uint64_t value) {
    __asm__ volatile("wrmsr" ::"a"((uint32_t)value),
                     "d"((uint32_t)(value >> 32)), "c"(msr));
}

#endif
