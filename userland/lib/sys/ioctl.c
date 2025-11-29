#include "ioctl.h"
#include <private.h>
#include <stdarg.h>

int ioctl(int fd, unsigned cmd, ...) {
    va_list args;
    va_start(args, cmd);
    unsigned long arg = va_arg(args, unsigned long);
    va_end(args);
    return __syscall_return(SYSCALL3(ioctl, fd, cmd, arg));
}
