#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void test_private(void) {
    unlink("/tmp/test-mmap-private");
    int fd = open("/tmp/test-mmap-private", O_CREAT | O_RDWR, 0644);
    ASSERT_OK(fd);

    size_t size = 30000 * sizeof(int);
    ASSERT_OK(ftruncate(fd, size));

    int* buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i)
        buf[i] = i;
    ASSERT_OK(munmap(buf, size));
    ASSERT_OK(munmap(buf, size));

    buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i) {
        ASSERT(buf[i] == i);
        buf[i] = i + 30000;
    }
    ASSERT_OK(munmap(buf, size));

    buf = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i)
        ASSERT(buf[i] == i);
    ASSERT_OK(munmap(buf, size));

    buf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i)
        ASSERT(buf[i] == i);
    ASSERT_OK(munmap(buf, size));

    ASSERT_OK(close(fd));
}

static void* shared_addr;

static _Noreturn void reader1(void) {
    for (size_t i = 0; i < 100; ++i)
        ASSERT(((uint32_t*)shared_addr)[i] == i);
    ASSERT_OK(munmap(shared_addr, 5000));
    exit(0);
}

static _Noreturn void reader2(void) {
    int fd = open("/tmp/test-mmap-shared", O_RDWR);
    ASSERT_OK(fd);
    size_t size = 50000 * sizeof(int);
    ASSERT_OK(ftruncate(fd, size));
    int* buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ASSERT(buf != MAP_FAILED);
    for (int i = 0; i < 30000; ++i)
        ASSERT(buf[i] == i);
    for (int i = 30000; i < 50000; ++i)
        buf[i] = i;
    ASSERT_OK(close(fd));
    ASSERT_OK(munmap(buf, size));
    exit(0);
}

static void test_shared(void) {
    size_t size = 5000;
    shared_addr = mmap(NULL, size, PROT_READ | PROT_WRITE,

                       MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    ASSERT(shared_addr != MAP_FAILED);
    for (size_t i = 0; i < 100; ++i)
        ((uint32_t*)shared_addr)[i] = i;
    pid_t pid = fork();
    ASSERT_OK(pid);
    if (pid == 0)
        reader1();
    ASSERT_OK(waitpid(pid, NULL, 0));
    ASSERT_OK(munmap(shared_addr, size));

    unlink("/tmp/test-mmap-shared");
    {
        int fd = open("/tmp/test-mmap-shared", O_RDWR | O_CREAT | O_EXCL, 0644);
        ASSERT_OK(fd);
        size_t size = 30000 * sizeof(int);
        ASSERT_OK(ftruncate(fd, size));
        int* buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        ASSERT(buf != MAP_FAILED);
        for (int i = 0; i < 30000; ++i)
            buf[i] = i;
        pid_t pid = fork();
        ASSERT_OK(pid);
        if (pid == 0)
            reader2();
        ASSERT_OK(waitpid(pid, NULL, 0));
        ASSERT_OK(close(fd));
        ASSERT_OK(munmap(buf, size));
    }
    {
        int fd = open("/tmp/test-mmap-shared", O_RDWR);
        ASSERT_OK(fd);
        size_t size = 50000 * sizeof(int);
        int* buf = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
        ASSERT(buf != MAP_FAILED);
        for (int i = 0; i < 30000; ++i)
            ASSERT(buf[i] == i);
        for (int i = 30000; i < 50000; ++i)
            ASSERT(buf[i] == i);
        ASSERT_OK(munmap(buf, size));
        ASSERT_OK(close(fd));
    }
    {
        int fd = open("/tmp/test-mmap-shared", O_RDWR);
        ASSERT_OK(fd);
        size_t size = 50000 * sizeof(int);
        int* buf = malloc(size);
        ASSERT(buf);
        ASSERT((size_t)read(fd, buf, size) == size);
        ASSERT_OK(close(fd));
        for (int i = 0; i < 30000; ++i)
            ASSERT(buf[i] == i);
        for (int i = 30000; i < 50000; ++i)
            ASSERT(buf[i] == i);
        free(buf);
    }
}

int main(void) {
    test_private();
    test_shared();
    return EXIT_SUCCESS;
}
