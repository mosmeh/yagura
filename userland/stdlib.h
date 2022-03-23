#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#define PANIC(msg) panic("PANIC: " msg, __FILE__, __LINE__)
#define UNREACHABLE() PANIC("Unreachable")
#define UNIMPLEMENTED() PANIC("Unimplemented")
#define ASSERT(cond) ((cond) ? (void)0 : PANIC("Assertion failed: " #cond))

noreturn void panic(const char* message, const char* file, size_t line);

typedef struct malloc_ctx {
    uintptr_t heap;
    uintptr_t ptr;
} malloc_ctx;

void malloc_init(malloc_ctx*);
void* malloc(malloc_ctx*, size_t size);
void* aligned_alloc(malloc_ctx*, size_t alignment, size_t size);

int printf(const char* format, ...);
