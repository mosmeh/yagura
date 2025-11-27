#include "ioctl.h"
#include <private.h>

int ioctl(int fd, int request, void* argp) {
    return __syscall_return(SYSCALL3(ioctl, fd, request, argp));
}
