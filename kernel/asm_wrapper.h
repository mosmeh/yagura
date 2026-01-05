#pragma once

#include <stdint.h>
#include <stdnoreturn.h>

uintptr_t read_eip(void);

static inline uint32_t read_eflags(void) {
    unsigned long flags;
    __asm__ volatile("pushf\n"
                     "pop %0"
                     : "=r"(flags));
    return flags;
}

static inline unsigned long read_cr0(void) {
    unsigned long cr0;
    __asm__("mov %%cr0, %%eax" : "=a"(cr0));
    return cr0;
}

static inline void write_cr0(unsigned long value) {
    __asm__ volatile("mov %%eax, %%cr0" ::"a"(value));
}

static inline unsigned long read_cr2(void) {
    unsigned long cr2;
    __asm__("mov %%cr2, %%eax" : "=a"(cr2));
    return cr2;
}

static inline unsigned long read_cr3(void) {
    unsigned long cr3;
    __asm__ volatile("mov %%cr3, %%eax" : "=a"(cr3));
    return cr3;
}

static inline void write_cr3(unsigned long cr3) {
    __asm__ volatile("mov %%eax, %%cr3" ::"a"(cr3) : "memory");
}

static inline unsigned long read_cr4(void) {
    unsigned long cr4;
    __asm__("mov %%cr4, %%eax" : "=a"(cr4));
    return cr4;
}

static inline void write_cr4(unsigned long value) {
    __asm__ volatile("mov %%eax, %%cr4" ::"a"(value));
}

static inline void flush_tlb(void) { write_cr3(read_cr3()); }

static inline void flush_tlb_single(uintptr_t virt_addr) {
    __asm__ volatile("invlpg (%0)" ::"r"(virt_addr) : "memory");
}

static inline uint8_t in8(uint16_t port) {
    uint8_t rv;
    __asm__ volatile("inb %1, %0" : "=a"(rv) : "dN"(port));
    return rv;
}

static inline uint16_t in16(uint16_t port) {
    uint16_t rv;
    __asm__ volatile("inw %1, %0" : "=a"(rv) : "dN"(port));
    return rv;
}

static inline uint32_t in32(uint16_t port) {
    uint32_t rv;
    __asm__ volatile("inl %1, %0" : "=a"(rv) : "dN"(port));
    return rv;
}

static inline void out8(uint16_t port, uint8_t data) {
    __asm__ volatile("outb %1, %0" : : "dN"(port), "a"(data));
}

static inline void out16(uint16_t port, uint16_t data) {
    __asm__ volatile("outw %1, %0" : : "dN"(port), "a"(data));
}

static inline void out32(uint16_t port, uint32_t data) {
    __asm__ volatile("outl %1, %0" : : "dN"(port), "a"(data));
}

static inline void delay(unsigned long usec) {
    uint8_t dummy;
    while (usec--)
        __asm__ volatile("inb $0x80, %0" : "=a"(dummy));
}

static inline void hlt(void) { __asm__ volatile("hlt"); }

static inline noreturn void ud2(void) {
    __asm__ volatile("ud2");
    __builtin_unreachable();
}

static inline void pause(void) { __asm__ volatile("pause"); }

// NOLINTBEGIN(readability-non-const-parameter)
static inline void cpuid(uint32_t function, uint32_t* eax, uint32_t* ebx,
                         uint32_t* ecx, uint32_t* edx) {
    // NOLINTEND(readability-non-const-parameter)
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "a"(function), "c"(0));
}

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
