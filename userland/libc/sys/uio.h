#pragma once

#include <kernel/api/sys/uio.h>
#include <sys/types.h>

ssize_t readv(int fd, const struct iovec* iov, int iovcnt);
ssize_t writev(int fd, const struct iovec* iov, int iovcnt);

ssize_t preadv(int fd, const struct iovec* iov, int iovcnt, off_t offset);
ssize_t pwritev(int fd, const struct iovec* iov, int iovcnt, off_t offset);

ssize_t preadv2(int fd, const struct iovec* iov, int iovcnt, off_t offset,
                int flags);
ssize_t pwritev2(int fd, const struct iovec* iov, int iovcnt, off_t offset,
                 int flags);

ssize_t process_vm_readv(pid_t pid, const struct iovec* local_iov,
                         unsigned long liovcnt, const struct iovec* remote_iov,
                         unsigned long riovcnt, unsigned long flags);
ssize_t process_vm_writev(pid_t pid, const struct iovec* local_iov,
                          unsigned long liovcnt, const struct iovec* remote_iov,
                          unsigned long riovcnt, unsigned long flags);
