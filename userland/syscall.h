#pragma once

#include <common/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

uintptr_t invoke_syscall(uint32_t num, uintptr_t arg1, uintptr_t arg2,
                         uintptr_t arg3);

noreturn void exit(int status);
pid_t fork(void);
pid_t getpid(void);

void yield(void);
void halt(void);

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset);

int puts(const char* str);

int open(const char* pathname, int flags);
int close(int fd);
ssize_t read(int fd, void* buf, size_t count);
ssize_t write(int fd, const void* buf, size_t count);
