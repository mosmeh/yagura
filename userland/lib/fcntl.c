#include "fcntl.h"
#include "private.h"
#include <stdarg.h>

int open(const char* pathname, int flags, ...) {
    unsigned mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, unsigned);
        va_end(args);
    }
    RETURN_WITH_ERRNO(int, SYSCALL3(open, pathname, flags, mode));
}

int fcntl(int fd, int cmd, ...) {
    va_list args;
    va_start(args, cmd);
    int arg = va_arg(args, int);
    va_end(args);
    RETURN_WITH_ERRNO(int, SYSCALL3(fcntl, fd, cmd, arg));
}
