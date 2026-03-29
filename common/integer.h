#pragma once

#include <common/ctype.h>
#include <common/stdbool.h>
#include <common/stddef.h>
#include <common/stdint.h>

#define ROUND_UP(x, align)                                                     \
    __extension__({                                                            \
        __typeof__(x) __x = (x);                                               \
        __typeof__(align) __align = (align);                                   \
        __typeof__(__x % __align) __mod = __x % __align;                       \
        __mod == 0 ? __x : __x + (__align - __mod);                            \
    })
#define ROUND_DOWN(x, align)                                                   \
    __extension__({                                                            \
        __typeof__(x) __x = (x);                                               \
        __x - (__x % (align));                                                 \
    })

#define DIV_CEIL(lhs, rhs) (((lhs) + (rhs) - 1) / (rhs))

static inline bool is_power_of_two(size_t x) { return x && (x & (x - 1)) == 0; }

static inline size_t ilog2(size_t x) {
    if (x == 0)
        return 0;
    return SIZE_WIDTH - __builtin_clzl(x) - 1;
}

static inline size_t next_power_of_two(size_t x) {
    if (x == 0)
        return 1;
    if (is_power_of_two(x))
        return x;
    return 1ULL << (ilog2(x) + 1);
}

static inline bool str_is_uint(const char* s) {
    while (*s) {
        if (!isdigit(*s))
            return false;
        ++s;
    }
    return true;
}
