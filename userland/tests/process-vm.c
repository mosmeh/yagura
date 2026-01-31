#include <common/macros.h>
#include <errno.h>
#include <panic.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static size_t read_all(int fd, void* buf, size_t count) {
    unsigned char* p = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t n = read(fd, p + total, count - total);
        ASSERT_OK(n);
        total += n;
    }
    return total;
}

static size_t write_all(int fd, const void* buf, size_t count) {
    const unsigned char* p = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t nwritten = write(fd, p + total, count - total);
        ASSERT_OK(nwritten);
        total += nwritten;
    }
    return total;
}

int main(void) {
    {

        char buf[5010];
        struct iovec local[1] = {
            {buf, sizeof(buf)},
        };

        void* none =
            mmap(NULL, 8192, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        ASSERT(none != MAP_FAILED);

        struct iovec remote1[1] = {
            {none, 5000},
        };

        errno = 0;
        ASSERT_ERR(process_vm_readv(getpid(), local, ARRAY_SIZE(local), remote1,
                                    ARRAY_SIZE(remote1), 0));
        ASSERT(errno == EFAULT);

        errno = 0;
        ASSERT_ERR(process_vm_writev(getpid(), local, ARRAY_SIZE(local),
                                     remote1, ARRAY_SIZE(remote1), 0));
        ASSERT(errno == EFAULT);

        void* read_only =
            mmap(NULL, 8192, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        ASSERT(read_only != MAP_FAILED);

        struct iovec remote2[1] = {
            {read_only, 5000},
        };

        ASSERT(process_vm_readv(getpid(), local, ARRAY_SIZE(local), remote2,
                                ARRAY_SIZE(remote2), 0) == 5000);

        errno = 0;
        ASSERT_ERR(process_vm_writev(getpid(), local, ARRAY_SIZE(local),
                                     remote2, ARRAY_SIZE(remote2), 0));
        ASSERT(errno == EFAULT);

        void* write_only =
            mmap(NULL, 8192, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        ASSERT(write_only != MAP_FAILED);

        struct iovec remote3[1] = {
            {write_only, 5000},
        };

        ASSERT(process_vm_writev(getpid(), local, ARRAY_SIZE(local), remote3,
                                 ARRAY_SIZE(remote3), 0) == 5000);

        errno = 0;
        ASSERT_ERR(process_vm_readv(getpid(), local, ARRAY_SIZE(local), remote3,
                                    ARRAY_SIZE(remote3), 0));
        ASSERT(errno == EFAULT);
    }

    {
        int pipes[2];
        ASSERT_OK(pipe(pipes));

        pid_t pid = fork();
        ASSERT_OK(pid);

        if (pid == 0) {
            char* buffer = malloc(32);
            ASSERT(buffer);
            memset(buffer, 0xff, 32);
            strcpy(buffer, "Hello, world!");
            write_all(pipes[1], &buffer, sizeof(void*));

            volatile char* p = buffer;
            for (size_t i = 0; i < 20; ++i) {
                while (p[i] != "foobarbaz1quxquuxquu"[i])
                    sched_yield();
            }
            for (size_t i = 20; i < 32; ++i)
                ASSERT(p[i] == (char)0xff);

            exit(EXIT_SUCCESS);
        }

        errno = 0;
        ASSERT_ERR(process_vm_readv(pid, NULL, 0, NULL, 0, ~0));
        ASSERT(errno == EINVAL);

        ASSERT(process_vm_readv(pid, NULL, 0, NULL, 0, 0) == 0);

        char buf1[10];
        char buf2[10];
        memset(buf1, 0xfe, sizeof(buf1));
        memset(buf2, 0xfe, sizeof(buf2));
        struct iovec local[3] = {
            {buf1, sizeof(buf1)},
            {NULL, 0},
            {buf2, sizeof(buf2)},
        };

        void* ptr;
        ASSERT(read_all(pipes[0], &ptr, sizeof(void*)) == sizeof(void*));

        struct iovec remote[2] = {
            {NULL, 0},
            {ptr, 20},
        };

        ASSERT(process_vm_readv(pid, local, ARRAY_SIZE(local), remote,
                                ARRAY_SIZE(remote), 0) == 20);
        ASSERT(memcmp(buf1, "Hello, wor", sizeof(buf1)) == 0);
        ASSERT(memcmp(buf2, "ld!\0\xff\xff\xff\xff\xff\xff", sizeof(buf2)) ==
               0);

        memcpy(buf1, "foobarbaz1", 10);
        memcpy(buf2, "quxquuxquu", 10);
        ASSERT(process_vm_writev(pid, local, ARRAY_SIZE(local), remote,
                                 ARRAY_SIZE(remote), 0) == 20);

        int status;
        ASSERT_OK(waitpid(pid, &status, 0));
        ASSERT(WIFEXITED(status));
        ASSERT(WEXITSTATUS(status) == EXIT_SUCCESS);
    }

    return EXIT_SUCCESS;
}
