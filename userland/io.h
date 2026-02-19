#pragma once

#include <common/macros.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

NODISCARD static inline ssize_t read_to_end(int fd, void* buf, size_t count) {
    unsigned char* p = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t n = read(fd, p + total, count - total);
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        total += n;
    }
    return total;
}

NODISCARD static inline ssize_t read_exact(int fd, void* buf, size_t count) {
    ssize_t nread = read_to_end(fd, buf, count);
    if (nread < 0)
        return -1;
    if ((size_t)nread != count) {
        errno = EPIPE;
        return -1;
    }
    return nread;
}

NODISCARD static inline ssize_t write_all(int fd, const void* buf,
                                          size_t count) {
    const unsigned char* p = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t n = write(fd, p + total, count - total);
        if (n == 0) {
            errno = EPIPE;
            return -1;
        }
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        total += n;
    }
    return total;
}
