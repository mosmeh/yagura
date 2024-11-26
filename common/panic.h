#pragma once

#include <stddef.h>
#include <stdnoreturn.h>

#define PANIC(...) panic(__FILE__, __LINE__, __VA_ARGS__)
#define UNREACHABLE() PANIC("Unreachable")
#define UNIMPLEMENTED() PANIC("Unimplemented")
#define ASSERT(cond) ((cond) ? (void)0 : PANIC("Assertion failed: " #cond))

noreturn void panic(const char* file, size_t line, const char* message, ...);
