#pragma once

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

void* memset(void* s, int c, size_t n);
void* memcpy(void* dest_ptr, const void* src_ptr, size_t n);

int strcmp(const char* s1, const char* s2);
int strncmp(const char* s1, const char* s2, size_t n);

size_t strlen(const char* str);
size_t strnlen(const char* str, size_t n);

char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);

int sprintf(char* buffer, const char* format, ...);
int vsnprintf(char* buffer, size_t size, const char* format, va_list args);

void str_replace_char(char* str, char from, char to);
