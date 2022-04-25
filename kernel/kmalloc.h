#pragma once

#include <stddef.h>

void* kmalloc(size_t size);
void* kaligned_alloc(size_t alignment, size_t size);

char* kstrdup(const char*);
char* kstrndup(const char*, size_t n);
