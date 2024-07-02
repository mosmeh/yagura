#pragma once

#include "api/err.h"
#include <common/extra.h>
#include <stddef.h>
#include <stdnoreturn.h>

#define PANIC(...) panic(__FILE__, __LINE__, __VA_ARGS__)
#define UNREACHABLE() PANIC("Unreachable")
#define UNIMPLEMENTED() PANIC("Unimplemented")
#define ASSERT(cond) ((cond) ? (void)0 : PANIC("Assertion failed: " #cond))
#define ASSERT_OK(result) ASSERT(IS_OK(result))

noreturn void panic(const char* file, size_t line, const char* message, ...);
