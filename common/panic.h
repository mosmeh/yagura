#pragma once

#include <stddef.h>
#include <stdnoreturn.h>

#define PANIC(...) panic(__FILE__, __LINE__, __VA_ARGS__)
#define UNREACHABLE() PANIC("Unreachable")
#define UNIMPLEMENTED() PANIC("Unimplemented")
#define ASSERT(cond)                                                           \
    ({                                                                         \
        __typeof__(cond) _cond = (cond);                                       \
        if (!_cond)                                                            \
            PANIC("Assertion failed: " #cond);                                 \
        _cond;                                                                 \
    })

noreturn void panic(const char* file, size_t line, const char* message, ...);
