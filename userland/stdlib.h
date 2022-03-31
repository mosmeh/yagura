#pragma once

#include <stddef.h>
#include <stdint.h>

void* malloc(size_t size);
void* aligned_alloc(size_t alignment, size_t size);
void free(void* ptr);

int printf(const char* format, ...);
