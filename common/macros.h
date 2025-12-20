#pragma once

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

#define NODISCARD __attribute__((__warn_unused_result__))
#define NOINLINE __attribute__((noinline))
#define STATIC_ASSERT(x) _Static_assert(x, "Static assertion failed")

#define PRINTF_LIKE(a, b) __attribute__((format(printf, a, b)))
