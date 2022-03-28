#include "syscall.h"
#include <common/extra.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/mman.h>
#include <kernel/api/syscall.h>
#include <stdarg.h>

uintptr_t syscall(uint32_t num, uintptr_t arg1, uintptr_t arg2,
                  uintptr_t arg3) {
    uintptr_t ret;
    __asm__ volatile("int $" STRINGIFY(SYSCALL_VECTOR)
                     : "=a"(ret)
                     : "a"(num), "d"(arg1), "c"(arg2), "b"(arg3)
                     : "memory");
    return ret;
}

noreturn void exit(int status) {
    syscall(SYS_exit, status, 0, 0);
    __builtin_unreachable();
}

pid_t fork(void) { return syscall(SYS_fork, 0, 0, 0); }

pid_t getpid(void) { return syscall(SYS_getpid, 0, 0, 0); }

void sched_yield(void) { syscall(SYS_yield, 0, 0, 0); }

void halt(void) { syscall(SYS_halt, 0, 0, 0); }

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
    mmap_params params;
    params.addr = addr;
    params.length = length;
    params.prot = prot;
    params.flags = flags;
    params.fd = fd;
    params.offset = offset;

    uintptr_t ret = syscall(SYS_mmap, (uintptr_t)&params, 0, 0);
    if (IS_ERR(ret))
        return MAP_FAILED;
    return (void*)ret;
}

int puts(const char* str) { return syscall(SYS_puts, (uintptr_t)str, 0, 0); }

int open(const char* pathname, int flags, ...) {
    unsigned mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, unsigned);
        va_end(args);
    }
    return syscall(SYS_open, (uintptr_t)pathname, flags, mode);
}

int close(int fd) { return syscall(SYS_close, fd, 0, 0); }

ssize_t read(int fd, void* buf, size_t count) {
    return syscall(SYS_read, fd, (uintptr_t)buf, count);
}

ssize_t write(int fd, const void* buf, size_t count) {
    return syscall(SYS_write, fd, (uintptr_t)buf, count);
}

int ioctl(int fd, int request, void* argp) {
    return syscall(SYS_ioctl, fd, request, (uintptr_t)argp);
}
