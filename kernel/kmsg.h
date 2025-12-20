#pragma once

#include <common/macros.h>
#include <stdarg.h>
#include <stddef.h>

#define KMSG_BUF_SIZE 16384

int kprint(const char*);
int kprintf(const char* format, ...) PRINTF_LIKE(1, 2);
int kvprintf(const char* format, va_list args) PRINTF_LIKE(1, 0);

size_t kmsg_read(char* buf, size_t count);
void kmsg_write(const char* buf, size_t count);
