#pragma once

#include <stdint.h>

static inline uint8_t __in8(uint16_t port) {
    uint8_t rv;
    __asm__ volatile("inb %1, %0" : "=a"(rv) : "dN"(port));
    return rv;
}

static inline uint16_t __in16(uint16_t port) {
    uint16_t rv;
    __asm__ volatile("inw %1, %0" : "=a"(rv) : "dN"(port));
    return rv;
}

static inline uint32_t __in32(uint16_t port) {
    uint32_t rv;
    __asm__ volatile("inl %1, %0" : "=a"(rv) : "dN"(port));
    return rv;
}

static inline void __out8(uint16_t port, uint8_t data) {
    __asm__ volatile("outb %1, %0" : : "dN"(port), "a"(data));
}

static inline void __out16(uint16_t port, uint16_t data) {
    __asm__ volatile("outw %1, %0" : : "dN"(port), "a"(data));
}

static inline void __out32(uint16_t port, uint32_t data) {
    __asm__ volatile("outl %1, %0" : : "dN"(port), "a"(data));
}

static inline void __delay(unsigned long usec) {
    uint8_t dummy;
    while (usec--)
        __asm__ volatile("inb $0x80, %0" : "=a"(dummy));
}

#define in8 __in8
#define in16 __in16
#define in32 __in32
#define out8 __out8
#define out16 __out16
#define out32 __out32
#define delay __delay
