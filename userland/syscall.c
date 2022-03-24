#include "syscall.h"
#include <common/extra.h>
#include <common/syscall.h>

uintptr_t invoke_syscall(uint32_t num, uintptr_t arg1, uintptr_t arg2,
                         uintptr_t arg3) {
    uintptr_t ret;
    __asm__ volatile("int $" STRINGIFY(SYSCALL_VECTOR)
                     : "=a"(ret)
                     : "a"(num), "d"(arg1), "c"(arg2), "b"(arg3)
                     : "memory");
    return ret;
}

noreturn void exit(int status) {
    invoke_syscall(SYS_EXIT, status, 0, 0);
    __builtin_unreachable();
}

pid_t fork(void) { return invoke_syscall(SYS_FORK, 0, 0, 0); }

pid_t getpid(void) { return invoke_syscall(SYS_GETPID, 0, 0, 0); }

void yield(void) { invoke_syscall(SYS_YIELD, 0, 0, 0); }

void halt(void) { invoke_syscall(SYS_HALT, 0, 0, 0); }

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
    mmap_params params;
    params.addr = addr;
    params.length = length;
    params.prot = prot;
    params.flags = flags;
    params.fd = fd;
    params.offset = offset;
    return (void*)invoke_syscall(SYS_MMAP, (uintptr_t)&params, 0, 0);
}

int puts(const char* str) {
    return invoke_syscall(SYS_PUTS, (uintptr_t)str, 0, 0);
}

int open(const char* pathname, int flags) {
    return invoke_syscall(SYS_OPEN, (uintptr_t)pathname, flags, 0);
}

int close(int fd) { return invoke_syscall(SYS_CLOSE, fd, 0, 0); }

ssize_t read(int fd, void* buf, size_t count) {
    return invoke_syscall(SYS_READ, fd, (uintptr_t)buf, count);
}

ssize_t write(int fd, const void* buf, size_t count) {
    return invoke_syscall(SYS_WRITE, fd, (uintptr_t)buf, count);
}
