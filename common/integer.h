#pragma once

#include <common/ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ROUND_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#define ROUND_DOWN(x, align) ((x) & ~((align) - 1))
#define DIV_CEIL(lhs, rhs) (((lhs) + (rhs) - 1) / (rhs))

static inline size_t next_power_of_two(size_t x) {
    if (x <= 1)
        return 1;
    return (SIZE_MAX >> __builtin_clz(x - 1)) + 1;
}

static inline int32_t divmodi64(int64_t a, int32_t b, int32_t* rem) {
    int32_t q;
    int32_t r;
    __asm__("idivl %[b]"
            : "=a"(q), "=d"(r)
            : "d"((int32_t)(a >> 32)),
              "a"((int32_t)(a & 0xffffffff)), [b] "rm"(b));
    if (rem)
        *rem = r;
    return q;
}

static inline uint32_t divmodu64(uint64_t a, uint32_t b, uint32_t* rem) {
    uint32_t q;
    uint32_t r;
    __asm__("divl %[b]"
            : "=a"(q), "=d"(r)
            : "d"((uint32_t)(a >> 32)),
              "a"((uint32_t)(a & 0xffffffff)), [b] "rm"(b));
    if (rem)
        *rem = r;
    return q;
}

static inline bool str_is_uint(const char* s) {
    while (*s) {
        if (!isdigit(*s))
            return false;
        ++s;
    }
    return true;
}
