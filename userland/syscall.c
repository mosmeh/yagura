#include "syscall.h"
#include "stdlib.h"
#include <common/extra.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
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

#define RETURN_WITH_ERRNO(rc, type)                                            \
    do {                                                                       \
        if (IS_ERR(rc)) {                                                      \
            errno = -rc;                                                       \
            return (type)-1;                                                   \
        }                                                                      \
        return (type)rc;                                                       \
    } while (0);

noreturn void exit(int status) {
    syscall(SYS_exit, status, 0, 0);
    __builtin_unreachable();
}

pid_t fork(void) {
    int rc = syscall(SYS_fork, 0, 0, 0);
    RETURN_WITH_ERRNO(rc, pid_t)
}

pid_t getpid(void) {
    int rc = syscall(SYS_getpid, 0, 0, 0);
    RETURN_WITH_ERRNO(rc, pid_t)
}

int sched_yield(void) {
    int rc = syscall(SYS_yield, 0, 0, 0);
    RETURN_WITH_ERRNO(rc, int)
}

int execve(const char* pathname, char* const argv[], char* const envp[]) {
    int rc = syscall(SYS_execve, (uintptr_t)pathname, (uintptr_t)argv,
                     (uintptr_t)envp);
    RETURN_WITH_ERRNO(rc, int)
}

noreturn void halt(void) {
    syscall(SYS_halt, 0, 0, 0);
    __builtin_unreachable();
}

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
    mmap_params params;
    params.addr = addr;
    params.length = length;
    params.prot = prot;
    params.flags = flags;
    params.fd = fd;
    params.offset = offset;

    int rc = syscall(SYS_mmap, (uintptr_t)&params, 0, 0);
    RETURN_WITH_ERRNO(rc, void*)
}

int puts(const char* str) {
    int rc = syscall(SYS_puts, (uintptr_t)str, 0, 0);
    RETURN_WITH_ERRNO(rc, int)
}

int open(const char* pathname, int flags, ...) {
    unsigned mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, unsigned);
        va_end(args);
    }
    int rc = syscall(SYS_open, (uintptr_t)pathname, flags, mode);
    RETURN_WITH_ERRNO(rc, int)
}

int close(int fd) {
    int rc = syscall(SYS_close, fd, 0, 0);
    RETURN_WITH_ERRNO(rc, int)
}

ssize_t read(int fd, void* buf, size_t count) {
    int rc = syscall(SYS_read, fd, (uintptr_t)buf, count);
    RETURN_WITH_ERRNO(rc, ssize_t)
}

ssize_t write(int fd, const void* buf, size_t count) {
    int rc = syscall(SYS_write, fd, (uintptr_t)buf, count);
    RETURN_WITH_ERRNO(rc, ssize_t)
}

int ftruncate(int fd, off_t length) {
    int rc = syscall(SYS_ftruncate, fd, length, 0);
    RETURN_WITH_ERRNO(rc, int)
}

int ioctl(int fd, int request, void* argp) {
    int rc = syscall(SYS_ioctl, fd, request, (uintptr_t)argp);
    RETURN_WITH_ERRNO(rc, int)
}

int socket(int domain, int type, int protocol) {
    int rc = syscall(SYS_socket, domain, type, protocol);
    RETURN_WITH_ERRNO(rc, int)
}

int bind(int sockfd, const sockaddr* addr, socklen_t addrlen) {
    int rc = syscall(SYS_bind, sockfd, (uintptr_t)addr, addrlen);
    RETURN_WITH_ERRNO(rc, int)
}

int listen(int sockfd, int backlog) {
    int rc = syscall(SYS_listen, sockfd, backlog, 0);
    RETURN_WITH_ERRNO(rc, int)
}

int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    int rc = syscall(SYS_accept, sockfd, (uintptr_t)addr, (uintptr_t)addrlen);
    RETURN_WITH_ERRNO(rc, int)
}

int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    int rc = syscall(SYS_connect, sockfd, (uintptr_t)addr, addrlen);
    RETURN_WITH_ERRNO(rc, int)
}
