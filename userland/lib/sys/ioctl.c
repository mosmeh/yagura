#include "ioctl.h"
#include <private.h>

int ioctl(int fd, int request, void* argp) {
    RETURN_WITH_ERRNO(int, SYSCALL3(ioctl, fd, request, argp));
}
