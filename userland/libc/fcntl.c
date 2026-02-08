#include "private.h"
#include <common/stdarg.h>
#include <fcntl.h>

int open(const char* pathname, int flags, ...) {
    unsigned mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, unsigned);
        va_end(args);
    }
    return __syscall_return(SYSCALL3(open, pathname, flags, mode));
}

int openat(int dirfd, const char* pathname, int flags, mode_t mode) {
    return __syscall_return(SYSCALL4(openat, dirfd, pathname, flags, mode));
}

int creat(const char* pathname, mode_t mode) {
    return __syscall_return(SYSCALL2(creat, pathname, mode));
}

int fcntl(int fd, int cmd, ...) {
    va_list args;
    va_start(args, cmd);
    int arg = va_arg(args, int);
    va_end(args);
    return __syscall_return(SYSCALL3(fcntl, fd, cmd, arg));
}

#ifndef SYS_fcntl64
#define SYS_fcntl64 SYS_fcntl
#endif

int fcntl64(int fd, int cmd, ...) {
    va_list args;
    va_start(args, cmd);
    int arg = va_arg(args, int);
    va_end(args);
    return __syscall_return(SYSCALL3(fcntl64, fd, cmd, arg));
}
