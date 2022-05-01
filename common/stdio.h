#pragma once

#include <stdarg.h>
#include <stddef.h>

int sprintf(char* buffer, const char* format, ...);
int vsnprintf(char* buffer, size_t size, const char* format, va_list args);
