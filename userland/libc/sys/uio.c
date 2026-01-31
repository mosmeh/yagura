#include "../private.h"
#include <common/limits.h>
#include <errno.h>
#include <sys/uio.h>

ssize_t readv(int fd, const struct iovec* iov, int iovcnt) {
    return __syscall_return(SYSCALL3(readv, fd, iov, iovcnt));
}

ssize_t writev(int fd, const struct iovec* iov, int iovcnt) {
    return __syscall_return(SYSCALL3(writev, fd, iov, iovcnt));
}

ssize_t preadv(int fd, const struct iovec* iov, int iovcnt, off_t offset) {
    return preadv2(fd, iov, iovcnt, offset, 0);
}

ssize_t pwritev(int fd, const struct iovec* iov, int iovcnt, off_t offset) {
    return pwritev2(fd, iov, iovcnt, offset, 0);
}

// To avoid undefined behavior when shifting by LONG_WIDTH,
// shift by HALF_LONG_WIDTH twice.
#define HALF_LONG_WIDTH (LONG_WIDTH / 2)

ssize_t preadv2(int fd, const struct iovec* iov, int iovcnt, off_t offset,
                int flags) {
    if (offset < 0)
        return __syscall_return(-EINVAL);
    unsigned long offset_low = (unsigned long)offset & ULONG_MAX;
    unsigned long offset_high =
        ((unsigned long)offset >> HALF_LONG_WIDTH) >> HALF_LONG_WIDTH;
    return __syscall_return(
        SYSCALL6(preadv2, fd, iov, iovcnt, offset_low, offset_high, flags));
}

ssize_t pwritev2(int fd, const struct iovec* iov, int iovcnt, off_t offset,
                 int flags) {
    if (offset < 0)
        return __syscall_return(-EINVAL);
    unsigned long offset_low = (unsigned long)offset & ULONG_MAX;
    unsigned long offset_high =
        ((unsigned long)offset >> HALF_LONG_WIDTH) >> HALF_LONG_WIDTH;
    return __syscall_return(
        SYSCALL6(pwritev2, fd, iov, iovcnt, offset_low, offset_high, flags));
}

ssize_t process_vm_readv(pid_t pid, const struct iovec* local_iov,
                         unsigned long liovcnt, const struct iovec* remote_iov,
                         unsigned long riovcnt, unsigned long flags) {
    return __syscall_return(SYSCALL6(process_vm_readv, pid, local_iov, liovcnt,
                                     remote_iov, riovcnt, flags));
}

ssize_t process_vm_writev(pid_t pid, const struct iovec* local_iov,
                          unsigned long liovcnt, const struct iovec* remote_iov,
                          unsigned long riovcnt, unsigned long flags) {
    return __syscall_return(SYSCALL6(process_vm_writev, pid, local_iov, liovcnt,
                                     remote_iov, riovcnt, flags));
}
