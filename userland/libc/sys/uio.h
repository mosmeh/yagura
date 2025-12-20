#pragma once

#include <kernel/api/sys/uio.h>
#include <sys/types.h>

ssize_t readv(int fd, const struct iovec* iov, int iovcnt);
ssize_t writev(int fd, const struct iovec* iov, int iovcnt);
