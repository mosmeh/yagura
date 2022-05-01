#pragma once

#include <common/stdlib.h>
#include <stddef.h>
#include <stdnoreturn.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

noreturn void exit(int status);
noreturn void abort(void);

void* malloc(size_t size);
void* aligned_alloc(size_t alignment, size_t size);
void free(void* ptr);

char* getenv(const char* name);
