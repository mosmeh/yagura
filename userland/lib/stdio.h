#pragma once

#include <common/stdio.h>
#include <kernel/api/stdio.h>

extern const char* const sys_errlist[];

int putchar(int ch);
int puts(const char* str);
int printf(const char* format, ...) PRINTF_LIKE(1, 2);
int vprintf(const char* format, va_list ap) PRINTF_LIKE(1, 0);
int dprintf(int fd, const char* format, ...) PRINTF_LIKE(2, 3);
int vdprintf(int fd, const char* format, va_list ap) PRINTF_LIKE(2, 0);

void perror(const char*);

int getchar(void);

int remove(const char* pathname);

int dbgputs(const char* str);
