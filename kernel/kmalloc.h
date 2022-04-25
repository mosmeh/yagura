#pragma once

#include <stddef.h>

void* kmalloc(size_t size);
void* kaligned_alloc(size_t alignment, size_t size);
void kfree(void* ptr);

char* kstrdup(const char*);
char* kstrndup(const char*, size_t n);
