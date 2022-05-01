#pragma once

#include <stddef.h>

void* memset(void* s, int c, size_t n);
void* memcpy(void* dest_ptr, const void* src_ptr, size_t n);
void* memmove(void* dest_ptr, void const* src_ptr, size_t n);

int strcmp(const char* s1, const char* s2);
int strncmp(const char* s1, const char* s2, size_t n);

size_t strlen(const char* str);
size_t strnlen(const char* str, size_t n);

char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);
size_t strlcpy(char* dst, const char* src, size_t size);

void str_replace_char(char* str, char from, char to);

char* strchr(const char* str, int ch);

char* strtok_r(char* str, const char* sep, char** last);
