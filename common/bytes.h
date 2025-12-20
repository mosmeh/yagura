#pragma once

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

// NOLINTNEXTLINE(readability-non-const-parameter)
static inline void memset16(uint16_t* dest, uint16_t c, size_t n) {
    __asm__ volatile("rep stosw"
                     : "=D"(dest), "=c"(n)
                     : "D"(dest), "c"(n), "a"(c)
                     : "memory");
}

// NOLINTNEXTLINE(readability-non-const-parameter)
static inline void memset32(uint32_t* dest, uint32_t c, size_t n) {
    __asm__ volatile("rep stosl"
                     : "=D"(dest), "=c"(n)
                     : "D"(dest), "c"(n), "a"(c)
                     : "memory");
}

// NOLINTNEXTLINE(readability-non-const-parameter)
static inline void memcpy32(uint32_t* dest, const uint32_t* src, size_t n) {
    __asm__ volatile("rep movsl" : "+S"(src), "+D"(dest), "+c"(n)::"memory");
}
