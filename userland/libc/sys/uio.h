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
