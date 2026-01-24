#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>

int main(void) {
    unlink("/tmp/test-read-write");

    {
        int fd =
            open("/tmp/test-read-write", O_WRONLY | O_CREAT | O_EXCL, 0644);
        ASSERT_OK(fd);
        int* buf = malloc(50000 * sizeof(int));
        ASSERT(buf);
        for (int i = 0; i < 50000; ++i)
            buf[i] = i;
        ASSERT(write(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        ASSERT(write(fd, buf, 50000 * sizeof(int)) == 50000 * sizeof(int));
        free(buf);
        ASSERT_OK(close(fd));
    }
    {
        int fd = open("/tmp/test-read-write", O_RDWR);
        ASSERT_OK(fd);
        int* buf = malloc(50000 * sizeof(int));
        ASSERT(buf);
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
        int fd = open("/tmp/test-read-write", O_RDWR);
        ASSERT_OK(fd);
        int* buf = malloc(50000 * sizeof(int));
        ASSERT(buf);
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
        int fd = open("/tmp/test-read-write", O_RDONLY);
        ASSERT_OK(fd);
        int* buf = malloc(50000 * sizeof(int));
        ASSERT(buf);
        ASSERT(read(fd, buf, 1000 * sizeof(int)) == 1000 * sizeof(int));
        for (int i = 0; i < 1000; ++i)
            ASSERT(buf[i] == i);
        ASSERT(read(fd, buf, 50000 * sizeof(int)) == 0);
        ASSERT_OK(close(fd));
    }
    {
        int fd = open("/tmp/test-read-write", O_RDWR);
        ASSERT_OK(fd);

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
