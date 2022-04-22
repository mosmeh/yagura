#pragma once

#include <kernel/api/types.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#define PANIC(msg) panic("PANIC: " msg, __FILE__, __LINE__)
#define UNREACHABLE() PANIC("Unreachable")
#define UNIMPLEMENTED() PANIC("Unimplemented")
#define ASSERT(cond) ((cond) ? (void)0 : PANIC("Assertion failed: " #cond))
#define ASSERT_OK(result) ASSERT((result) >= 0)
#define ASSERT_ERR(result) ASSERT((result) < 0)

noreturn void panic(const char* message, const char* file, size_t line);

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

noreturn void abort(void);

void* malloc(size_t size);
void* aligned_alloc(size_t alignment, size_t size);
void free(void* ptr);

int putchar(int ch);
int puts(const char* str);
int printf(const char* format, ...);
int dprintf(int fd, const char* format, ...);
int vdprintf(int fd, const char* format, va_list ap);

extern int errno;
char* strerror(int errnum);
void perror(const char*);

extern char** environ;
char* getenv(const char* name);

int execvpe(const char* file, char* const argv[], char* const envp[]);

unsigned int sleep(unsigned int seconds);

typedef struct DIR DIR;
DIR* opendir(const char* name);
int closedir(DIR* dirp);
struct dirent* readdir(DIR* dirp);

clock_t clock(void);
