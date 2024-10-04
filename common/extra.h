#pragma once

#include "ctype.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define SIZEOF_FIELD(t, f) sizeof(((t*)0)->f)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define CONTAINER_OF(ptr, type, member)                                        \
    ({                                                                         \
        const __typeof__(((type*)0)->member)* __mptr = (ptr);                  \
        (type*)((char*)__mptr - offsetof(type, member));                       \
    })

#define ROUND_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#define ROUND_DOWN(x, align) ((x) & ~((align) - 1))
#define DIV_CEIL(lhs, rhs) (((lhs) + (rhs) - 1) / (rhs))

#define NODISCARD __attribute__((__warn_unused_result__))
#define NOINLINE __attribute__((noinline))
#define STATIC_ASSERT(x) _Static_assert(x, "Static assertion failed")

#define PRINTF_LIKE(a, b) __attribute__((format(printf, a, b)))

static inline size_t next_power_of_two(size_t x) {
    if (x <= 1)
        return 1;
    return (SIZE_MAX >> __builtin_clz(x - 1)) + 1;
}

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

static inline bool str_is_uint(const char* s) {
    while (*s) {
        if (!isdigit(*s))
            return false;
        ++s;
    }
    return true;
}

static inline void full_memory_barrier(void) {
    atomic_signal_fence(memory_order_acq_rel);
    atomic_thread_fence(memory_order_acq_rel);
}
