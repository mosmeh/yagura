#include "stdlib.h"
#include "syscall.h"
#include <common/panic.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/mman.h>

void child(void) {
    int fd = open("/dev/shm/foofoo", O_RDWR);
    ASSERT_OK(fd);
    int* buf = mmap(NULL, 30000 * sizeof(int), PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i)
        ASSERT(buf[i] == i);
    ASSERT_OK(close(fd));
    exit(0);
}

void _start(void) {
    int shm_fd = open("/dev/shm/foofoo", O_RDWR | O_CREAT | O_EXCL);
    ASSERT_OK(shm_fd);
    ASSERT_OK(ftruncate(shm_fd, 30000 * sizeof(int)));
    int* buf = mmap(NULL, 30000 * sizeof(int), PROT_READ | PROT_WRITE,
                    MAP_SHARED, shm_fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i)
        buf[i] = i;
    if (fork() == 0)
        child();
    {
        int fd = open("/tmp/wow", O_RDWR | O_CREAT);
        ASSERT_OK(fd);
        int* buf = malloc(65536 * sizeof(int));
        ASSERT(buf);
        for (int i = 0; i < 65536; ++i)
            buf[i] = i;
        ASSERT(write(fd, buf, 1024 * sizeof(int)) == 1024 * sizeof(int));
        ASSERT(write(fd, buf, 65536 * sizeof(int)) == 65536 * sizeof(int));
        free(buf);
        ASSERT_OK(close(fd));
    }
    {
        int fd = open("/tmp/wow", O_RDWR);
        ASSERT_OK(fd);
        int* buf = malloc(65536 * sizeof(int));
        ASSERT(buf);
        ASSERT(read(fd, buf, 1024 * sizeof(int)) == 1024 * sizeof(int));
        for (int i = 0; i < 1024; ++i)
            ASSERT(buf[i] == i);
        ASSERT(read(fd, buf, 65536 * sizeof(int)) == 65536 * sizeof(int));
        for (int i = 0; i < 65536; ++i)
            ASSERT(buf[i] == i);
        ASSERT_OK(ftruncate(fd, 1024 * sizeof(int)));
        for (int i = 0; i < 1024; ++i)
            buf[i] = 5 * i;
        ASSERT(write(fd, buf, 1024 * sizeof(int)) == 1024 * sizeof(int));
        ASSERT_OK(close(fd));
        free(buf);
    }
    {
        int fd = open("/tmp/wow", O_RDWR);
        int* buf = malloc(65536 * sizeof(int));
        ASSERT(buf);
        ASSERT(read(fd, buf, 1024 * sizeof(int)) == 1024 * sizeof(int));
        for (int i = 0; i < 1024; ++i)
            ASSERT(buf[i] == i);
        ASSERT(read(fd, buf, 65536 * sizeof(int)) == 65536 * sizeof(int));
        for (int i = 0; i < 65536; ++i)
            ASSERT(buf[i] == 0);
        ASSERT(read(fd, buf, 1024 * sizeof(int)) == 1024 * sizeof(int));
        for (int i = 0; i < 1024; ++i)
            ASSERT(buf[i] == 5 * i);
        ASSERT_OK(ftruncate(fd, 1024 * sizeof(int)));
        ASSERT_OK(close(fd));
    }
    {
        int fd = open("/tmp/wow", O_RDWR);
        int* buf = malloc(65536 * sizeof(int));
        ASSERT(buf);
        ASSERT(read(fd, buf, 1024 * sizeof(int)) == 1024 * sizeof(int));
        for (int i = 0; i < 1024; ++i)
            ASSERT(buf[i] == i);
        ASSERT(read(fd, buf, 65536 * sizeof(int)) == 0);
        ASSERT_OK(close(fd));
    }
    ASSERT_OK(close(shm_fd));
    exit(0);
}
