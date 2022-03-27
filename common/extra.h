#pragma once

#include "errno.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

static inline uintptr_t round_up(uintptr_t x, size_t align) {
    return (x + (align - 1)) & ~(align - 1);
}

static inline uintptr_t round_down(uintptr_t x, size_t align) {
    return x & ~(align - 1);
}

static inline size_t div_ceil(size_t lhs, size_t rhs) {
    return (lhs + rhs - 1) / rhs;
}

static inline bool addr_is_error(uintptr_t addr) {
    return -EMAXERRNO < (int)addr && (int)addr < 0;
}
