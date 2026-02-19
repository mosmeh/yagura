#pragma once

#include <common/stddef.h>

#define PANIC(format, ...)                                                     \
    panic("PANIC: " format " at %s:%d\n", ##__VA_ARGS__, __FILE__, __LINE__)

#define UNREACHABLE() PANIC("Unreachable")
#define UNIMPLEMENTED() PANIC("Unimplemented")

#define ASSERT(cond)                                                           \
    __extension__({                                                            \
        __typeof__(cond) __cond = (cond);                                      \
        if (!__cond)                                                           \
            PANIC("Assertion failed: " #cond);                                 \
        __cond;                                                                \
    })

_Noreturn void panic(const char* format, ...);
