#pragma once

#include <stddef.h>
#include <stdnoreturn.h>

#define KPANIC(msg) kpanic("PANIC: " msg, __FILE__, __LINE__)
#define KUNREACHABLE() KPANIC("Unreachable")
#define KUNIMPLEMENTED() KPANIC("Unimplemented")
#define KASSERT(cond) ((cond) ? (void)0 : KPANIC("Assertion failed: " #cond))

noreturn void kpanic(const char* message, const char* file, size_t line);
