#include "../io.h"
#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

int main(void) {
    unlink("/tmp/test-read-write");
    rmdir("/tmp/test-read-write-dir");

    {
        int fd = ASSERT_OK(
            open("/tmp/test-read-write", O_WRONLY | O_CREAT | O_EXCL, 0644));
        int* buf = ASSERT(malloc(50000 * sizeof(int)));
        for (int i = 0; i < 50000; ++i)
            buf[i] = i;
        ASSERT_OK(write_all(fd, buf, 1000 * sizeof(int)));
        ASSERT_OK(write_all(fd, buf, 50000 * sizeof(int)));
        free(buf);
        ASSERT_OK(close(fd));
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_RDWR));
        int* buf = ASSERT(malloc(50000 * sizeof(int)));
        ASSERT_OK(read_exact(fd, buf, 1000 * sizeof(int)));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == i);
        ASSERT_OK(read_exact(fd, buf, 50000 * sizeof(int)));
        for (int i = 0; i < 50000; ++i)
            ASSERT(buf[i] == i);
        ASSERT_OK(ftruncate(fd, 1000 * sizeof(int)));
        for (int i = 0; i < 1000; ++i)
            buf[i] = 5 * i;
        ASSERT_OK(write_all(fd, buf, 1000 * sizeof(int)));
        ASSERT_OK(close(fd));
        free(buf);
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_RDWR));
        int* buf = ASSERT(malloc(50000 * sizeof(int)));
        ASSERT_OK(read_exact(fd, buf, 1000 * sizeof(int)));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == i);
        ASSERT_OK(read_exact(fd, buf, 50000 * sizeof(int)));
        for (int i = 0; i < 50000; ++i)
            ASSERT(buf[i] == 0);
        ASSERT_OK(read_exact(fd, buf, 1000 * sizeof(int)));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == 5 * i);
        ASSERT_OK(ftruncate(fd, 1000 * sizeof(int)));
        ASSERT_OK(close(fd));
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_RDONLY));
        int* buf = ASSERT(malloc(50000 * sizeof(int)));
        ASSERT_OK(read_exact(fd, buf, 1000 * sizeof(int)));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == i);
        ASSERT(read_to_end(fd, buf, 50000 * sizeof(int)) == 0);
        ASSERT_OK(close(fd));
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_WRONLY));
        ASSERT_OK(write_all(fd, "x", 1));
        char x;
        ASSERT_ERRNO(read(fd, &x, 1), EBADF);
        ASSERT_OK(close(fd));
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_RDONLY));
        ASSERT_ERRNO(write(fd, "x", 1), EBADF);
        char x;
        ASSERT_OK(read_exact(fd, &x, 1));
        ASSERT_OK(close(fd));
    }
    {
        ASSERT_OK(mkdir("/tmp/test-read-write-dir", 0755));
        int fd = ASSERT_OK(open("/tmp/test-read-write-dir", O_RDONLY));
        ASSERT_ERRNO(read(fd, NULL, 100), EISDIR);
        ASSERT_ERRNO(write(fd, NULL, 100), EBADF);
        ASSERT_OK(close(fd));
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_RDWR));

        ASSERT_ERRNO(read(fd, NULL, 100), EFAULT);

        ASSERT(read(fd, NULL, 0) == 0);
        ASSERT(read(fd, (void*)1, 0) == 0);

        ASSERT_ERRNO(write(fd, NULL, 100), EFAULT);
        ASSERT_ERRNO(write(fd, (void*)1, 100), EFAULT);

        ASSERT(write(fd, NULL, 0) == 0);
        ASSERT(write(fd, (void*)1, 0) == 0);

        ASSERT_ERRNO(readv(fd, NULL, 1), EFAULT);
        ASSERT_ERRNO(readv(fd, (struct iovec*)1, 1), EFAULT);

        ASSERT(readv(fd, NULL, 0) == 0);
        ASSERT(readv(fd, (struct iovec*)1, 0) == 0);

        struct iovec iov;

        iov.iov_base = NULL;
        iov.iov_len = 100;
        ASSERT_ERRNO(readv(fd, &iov, 1), EFAULT);

        iov.iov_base = (void*)1;
        iov.iov_len = 100;
        ASSERT_ERRNO(readv(fd, &iov, 1), EFAULT);

        iov.iov_base = NULL;
        iov.iov_len = 0;
        ASSERT(readv(fd, &iov, 1) == 0);

        iov.iov_base = (void*)1;
        iov.iov_len = 0;
        ASSERT(readv(fd, &iov, 1) == 0);

        ASSERT_ERRNO(writev(fd, NULL, 1), EFAULT);
        ASSERT_ERRNO(writev(fd, (struct iovec*)1, 1), EFAULT);

        ASSERT(writev(fd, NULL, 0) == 0);
        ASSERT(writev(fd, (struct iovec*)1, 0) == 0);

        iov.iov_base = NULL;
        iov.iov_len = 100;
        ASSERT_ERRNO(writev(fd, &iov, 1), EFAULT);

        iov.iov_base = (void*)1;
        iov.iov_len = 100;
        ASSERT_ERRNO(writev(fd, &iov, 1), EFAULT);

        iov.iov_base = NULL;
        iov.iov_len = 0;
        ASSERT(writev(fd, &iov, 1) == 0);

        iov.iov_base = (void*)1;
        iov.iov_len = 0;
        ASSERT(writev(fd, &iov, 1) == 0);
    }

    return EXIT_SUCCESS;
}
