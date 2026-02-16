#pragma once

#include <common/stddef.h>

#define PANIC(...) panic(__FILE__, __LINE__, __VA_ARGS__)
#define UNREACHABLE() PANIC("Unreachable")
#define UNIMPLEMENTED() PANIC("Unimplemented")
#define ASSERT(cond)                                                           \
    __extension__({                                                            \
        __typeof__(cond) __cond = (cond);                                      \
        if (!__cond)                                                           \
            PANIC("Assertion failed: " #cond);                                 \
        __cond;                                                                \
    })

_Noreturn void panic(const char* file, size_t line, const char* message, ...);
