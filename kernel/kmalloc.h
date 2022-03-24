#pragma once

#include <stddef.h>

void kmalloc_init(void);
void* kmalloc(size_t size);
void* kaligned_alloc(size_t alignment, size_t size);
