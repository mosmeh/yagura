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
        ASSERT(write(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        ASSERT(write(fd, buf, 50000 * sizeof(int)) == 50000 * sizeof(int));
        free(buf);
        ASSERT_OK(close(fd));
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_RDWR));
        int* buf = ASSERT(malloc(50000 * sizeof(int)));
        ASSERT(read(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == i);
        ASSERT(read(fd, buf, 50000 * sizeof(int)) == 50000 * sizeof(int));
        for (int i = 0; i < 50000; ++i)
            ASSERT(buf[i] == i);
        ASSERT_OK(ftruncate(fd, 1000 * sizeof(int)));
        for (int i = 0; i < 1000; ++i)
            buf[i] = 5 * i;
        ASSERT(write(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        ASSERT_OK(close(fd));
        free(buf);
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_RDWR));
        int* buf = ASSERT(malloc(50000 * sizeof(int)));
        ASSERT(read(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == i);
        ASSERT(read(fd, buf, 50000 * sizeof(int)) == 50000 * sizeof(int));
        for (int i = 0; i < 50000; ++i)
            ASSERT(buf[i] == 0);
        ASSERT(read(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == 5 * i);
        ASSERT_OK(ftruncate(fd, 1000 * sizeof(int)));
        ASSERT_OK(close(fd));
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_RDONLY));
        int* buf = ASSERT(malloc(50000 * sizeof(int)));
        ASSERT(read(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == i);
        ASSERT(read(fd, buf, 50000 * sizeof(int)) == 0);
        ASSERT_OK(close(fd));
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_WRONLY));
        ASSERT(write(fd, "x", 1) == 1);

        char x;
        errno = 0;
        ASSERT_ERR(read(fd, &x, 1));
        ASSERT(errno == EBADF);

        ASSERT_OK(close(fd));
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_RDONLY));

        errno = 0;
        ASSERT_ERR(write(fd, "x", 1));
        ASSERT(errno == EBADF);

        char x;
        ASSERT(read(fd, &x, 1) == 1);
        ASSERT_OK(close(fd));
    }
    {
        ASSERT_OK(mkdir("/tmp/test-read-write-dir", 0755));
        int fd = ASSERT_OK(open("/tmp/test-read-write-dir", O_RDONLY));

        errno = 0;
        ASSERT_ERR(read(fd, NULL, 100));
        ASSERT(errno == EISDIR);

        errno = 0;
        ASSERT_ERR(write(fd, NULL, 100));
        ASSERT(errno == EBADF);

        ASSERT_OK(close(fd));
    }
    {
        int fd = ASSERT_OK(open("/tmp/test-read-write", O_RDWR));

        errno = 0;
        ASSERT_ERR(read(fd, NULL, 100));
        ASSERT(errno == EFAULT);

        ASSERT(read(fd, NULL, 0) == 0);
        ASSERT(read(fd, (void*)1, 0) == 0);

        errno = 0;
        ASSERT_ERR(write(fd, NULL, 100));
        ASSERT(errno == EFAULT);

        errno = 0;
        ASSERT_ERR(write(fd, (void*)1, 100));
        ASSERT(errno == EFAULT);

        ASSERT(write(fd, NULL, 0) == 0);
        ASSERT(write(fd, (void*)1, 0) == 0);

        errno = 0;
        ASSERT_ERR(readv(fd, NULL, 1));
        ASSERT(errno == EFAULT);

        errno = 0;
        ASSERT_ERR(readv(fd, (struct iovec*)1, 1));
        ASSERT(errno == EFAULT);

        ASSERT(readv(fd, NULL, 0) == 0);
        ASSERT(readv(fd, (struct iovec*)1, 0) == 0);

        struct iovec iov;

        iov.iov_base = NULL;
        iov.iov_len = 100;
        errno = 0;
        ASSERT_ERR(readv(fd, &iov, 1));
        ASSERT(errno == EFAULT);

        iov.iov_base = (void*)1;
        iov.iov_len = 100;
        errno = 0;
        ASSERT_ERR(readv(fd, &iov, 1));
        ASSERT(errno == EFAULT);

        iov.iov_base = NULL;
        iov.iov_len = 0;
        ASSERT(readv(fd, &iov, 1) == 0);

        iov.iov_base = (void*)1;
        iov.iov_len = 0;
        ASSERT(readv(fd, &iov, 1) == 0);

        errno = 0;
        ASSERT_ERR(writev(fd, NULL, 1));
        ASSERT(errno == EFAULT);

        errno = 0;
        ASSERT_ERR(writev(fd, (struct iovec*)1, 1));
        ASSERT(errno == EFAULT);

        ASSERT(writev(fd, NULL, 0) == 0);
        ASSERT(writev(fd, (struct iovec*)1, 0) == 0);

        iov.iov_base = NULL;
        iov.iov_len = 100;
        errno = 0;
        ASSERT_ERR(writev(fd, &iov, 1));
        ASSERT(errno == EFAULT);

        iov.iov_base = (void*)1;
        iov.iov_len = 100;
        errno = 0;
        ASSERT_ERR(writev(fd, &iov, 1));
        ASSERT(errno == EFAULT);

        iov.iov_base = NULL;
        iov.iov_len = 0;
        ASSERT(writev(fd, &iov, 1) == 0);

        iov.iov_base = (void*)1;
        iov.iov_len = 0;
        ASSERT(writev(fd, &iov, 1) == 0);
    }

    return EXIT_SUCCESS;
}
