#include "uio.h"
#include <private.h>

ssize_t readv(int fd, const struct iovec* iov, int iovcnt) {
    RETURN_WITH_ERRNO(ssize_t, SYSCALL3(readv, fd, iov, iovcnt));
}

ssize_t writev(int fd, const struct iovec* iov, int iovcnt) {
    RETURN_WITH_ERRNO(ssize_t, SYSCALL3(writev, fd, iov, iovcnt));
}
