#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#define PANIC(msg) panic("PANIC: " msg, __FILE__, __LINE__)
#define UNREACHABLE() PANIC("Unreachable")
#define UNIMPLEMENTED() PANIC("Unimplemented")
#define ASSERT(cond) ((cond) ? (void)0 : PANIC("Assertion failed: " #cond))
#define ASSERT_OK(result) ASSERT((result) >= 0)

noreturn void panic(const char* message, const char* file, size_t line);

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

noreturn void abort(void);

void* malloc(size_t size);
void* aligned_alloc(size_t alignment, size_t size);
void free(void* ptr);

int printf(const char* format, ...);

extern int errno;
char* strerror(int errnum);
void perror(const char*);

unsigned int sleep(unsigned int seconds);
