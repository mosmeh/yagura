#pragma once

#include <common/stddef.h>
#include <common/stdlib.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define RAND_MAX 2147483647

_Noreturn void exit(int status);
_Noreturn void abort(void);

void* malloc(size_t size);
void* aligned_alloc(size_t alignment, size_t size);
void* calloc(size_t num, size_t size);
void* realloc(void* ptr, size_t new_size);
void free(void* ptr);

char* getenv(const char* name);

int rand(void);
void srand(unsigned seed);
