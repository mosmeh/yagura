#pragma once

#include <common/macros.h>
#include <common/stdarg.h>
#include <common/stddef.h>

#define KMSG_BUF_CAPACITY 16384

int kprint(const char*);
int kprintf(const char* format, ...) PRINTF_LIKE(1, 2);
int kvprintf(const char* format, va_list args) PRINTF_LIKE(1, 0);

size_t kmsg_read(char* buf, size_t count, size_t offset);
void kmsg_write(const char* buf, size_t count);
size_t kmsg_size(void);
void kmsg_clear(void);
