#pragma once

#include <stddef.h>
#include <stdint.h>

static inline void memset16(uint16_t* dest, uint16_t c, size_t n) {
    for (size_t i = 0; i < n; ++i)
        dest[i] = c;
}

static inline void memcpy16(uint16_t* dest, const uint16_t* src, size_t n) {
    for (size_t i = 0; i < n; ++i)
        dest[i] = src[i];
}

static inline void memset32(uint32_t* dest, uint32_t c, size_t n) {
    for (size_t i = 0; i < n; ++i)
        dest[i] = c;
}

static inline void memcpy32(uint32_t* dest, const uint32_t* src, size_t n) {
    for (size_t i = 0; i < n; ++i)
        dest[i] = src[i];
}
