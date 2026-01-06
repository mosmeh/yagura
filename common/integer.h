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

static inline bool str_is_uint(const char* s) {
    while (*s) {
        if (!isdigit(*s))
            return false;
        ++s;
    }
    return true;
}
