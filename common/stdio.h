#pragma once

#include <common/extra.h>
#include <stdarg.h>
#include <stddef.h>

int sprintf(char* buffer, const char* format, ...) PRINTF_LIKE(2, 3);
int snprintf(char* buffer, size_t bufsz, const char* format, ...)
    PRINTF_LIKE(3, 4);
int vsprintf(char* buffer, const char* format, va_list args) PRINTF_LIKE(2, 0);
int vsnprintf(char* buffer, size_t size, const char* format, va_list args)
    PRINTF_LIKE(3, 0);
