#include <errno.h>
#include <panic.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
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

    char buf1[10];
    char buf2[10];
    memset(buf1, 0xfe, sizeof(buf1));
    memset(buf2, 0xfe, sizeof(buf2));
    struct iovec local[2] = {
        {buf1, 10},
        {buf2, 10},
    };

    void* ptr;
    ASSERT_OK(read_all(pipes[0], &ptr, sizeof(void*)));

    struct iovec remote[1] = {
        {ptr, 20},
    };

    ASSERT(process_vm_readv(pid, local, 2, remote, 1, 0) == 20);
    ASSERT(memcmp(buf1, "Hello, wor", 10) == 0);
    ASSERT(memcmp(buf2, "ld!\0\xff\xff\xff\xff\xff\xff", 10) == 0);

    memcpy(buf1, "foobarbaz1", 10);
    memcpy(buf2, "quxquuxquu", 10);
    ASSERT(process_vm_writev(pid, local, 2, remote, 1, 0) == 20);

    int status;
    ASSERT_OK(waitpid(pid, &status, 0));
    ASSERT(WIFEXITED(status));
    ASSERT(WEXITSTATUS(status) == EXIT_SUCCESS);

    return EXIT_SUCCESS;
}
