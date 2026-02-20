#include "../io.h"
#include "private.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

int putchar(int ch) {
    char c = ch;
    if (write_all(STDOUT_FILENO, &c, 1) < 0)
        return EOF;
    return ch;
}

int puts(const char* str) {
    size_t len = strlen(str);
    struct iovec iovs[2] = {
        {.iov_base = (void*)str, .iov_len = len},
        {.iov_base = "\n", .iov_len = 1},
    };
    size_t nwritten = 0;
    while (nwritten < len + 1) {
        ssize_t n = writev(STDOUT_FILENO, iovs, 2);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return EOF;
        nwritten += n;
        if (nwritten >= len)
            break;
        iovs[0].iov_base = (char*)iovs[0].iov_base + n;
        iovs[0].iov_len -= n;
    }
    if (nwritten < len + 1) {
        if (write_all(STDOUT_FILENO, "\n", 1) < 0)
            return EOF;
        ++nwritten;
    }
    return nwritten;
}

int printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);
    return ret;
}

int vprintf(const char* format, va_list ap) {
    return vdprintf(STDOUT_FILENO, format, ap);
}

int dprintf(int fd, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vdprintf(fd, format, args);
    va_end(args);
    return ret;
}

int vdprintf(int fd, const char* format, va_list ap) {
    static _Thread_local char* buf;
    static _Thread_local size_t buf_size;

    int len = 80; // Initial size of the buffer
    for (;;) {
        if (buf) {
            va_list args_copy;
            va_copy(args_copy, ap);
            len = vsnprintf(buf, buf_size, format, args_copy);
            va_end(args_copy);
            if (len < 0)
                return -1;
            if ((size_t)len < buf_size)
                break;
        }
        size_t new_size = (size_t)len + 1;
        char* new_buf = realloc(buf, new_size);
        if (!new_buf)
            return -1;
        buf = new_buf;
        buf_size = new_size;
    }
    if (write_all(fd, buf, len) < 0)
        return -1;
    return len;
}

void perror(const char* s) {
    dprintf(STDERR_FILENO, "%s: %s\n", s, strerror(errno));
}

int getchar(void) {
    char c = EOF;
    if (read_exact(STDIN_FILENO, &c, 1) < 0)
        return EOF;
    return c;
}

int rename(const char* oldpath, const char* newpath) {
    return __syscall_return(SYSCALL2(rename, oldpath, newpath));
}

int renameat(int olddirfd, const char* oldpath, int newdirfd,
             const char* newpath) {
    return __syscall_return(
        SYSCALL4(renameat, olddirfd, oldpath, newdirfd, newpath));
}

int renameat2(int olddirfd, const char* oldpath, int newdirfd,
              const char* newpath, unsigned int flags) {
    return __syscall_return(
        SYSCALL5(renameat2, olddirfd, oldpath, newdirfd, newpath, flags));
}

int remove(const char* pathname) {
    if (unlink(pathname) >= 0)
        return 0;
    if (errno == EISDIR)
        return rmdir(pathname);
    return -1;
}

int dbgprint(const char* str) {
    return __syscall_return(SYSCALL1(dbgprint, str));
}
