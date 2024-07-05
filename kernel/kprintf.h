#pragma once

#include <common/extra.h>
#include <stdarg.h>

int kprint(const char*);
int kprintf(const char* format, ...) PRINTF_LIKE(1, 2);
int kvprintf(const char* format, va_list args) PRINTF_LIKE(1, 0);
