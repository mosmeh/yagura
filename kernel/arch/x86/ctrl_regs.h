#pragma once

static inline unsigned long read_cr0(void) {
    unsigned long cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    return cr0;
}

static inline void write_cr0(unsigned long value) {
    __asm__ volatile("mov %0, %%cr0" ::"r"(value));
}

static inline unsigned long read_cr2(void) {
    unsigned long cr2;
    __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
    return cr2;
}

static inline unsigned long read_cr3(void) {
    unsigned long cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

static inline void write_cr3(unsigned long cr3) {
    __asm__ volatile("mov %0, %%cr3" ::"r"(cr3) : "memory");
}

static inline unsigned long read_cr4(void) {
    unsigned long cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    return cr4;
}

static inline void write_cr4(unsigned long value) {
    __asm__ volatile("mov %0, %%cr4" ::"r"(value));
}
