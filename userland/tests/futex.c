#include "../io.h"
#include <common/integer.h>
#include <common/macros.h>
#include <linux/futex.h>
#include <panic.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef SYS_futex_time64
#undef SYS_futex
#define SYS_futex SYS_futex_time64
#endif

NODISCARD static long futex(uint32_t* uaddr, int futex_op, uint32_t val,
                            const struct timespec* timeout, uint32_t* uaddr2,
                            uint32_t val3) {
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

NODISCARD static int futex_wait(uint32_t* uaddr, uint32_t val,
                                const struct timespec* timeout) {
    return futex(uaddr, FUTEX_WAIT, val, timeout, NULL, 0);
}

NODISCARD static ssize_t futex_wake(uint32_t* uaddr, uint32_t val) {
    return futex(uaddr, FUTEX_WAKE, val, NULL, NULL, 0);
}

static void wake_one(uint32_t* uaddr, int op) {
    for (;;) {
        errno = 0;
        ssize_t n = futex(uaddr, op, 1, NULL, NULL, 0);
        if (n < 0) {
            ASSERT(errno == EAGAIN);
            continue;
        }
        ASSERT(n == 0 || n == 1);
        if (n > 0)
            break;
        usleep(1000);
    }
}

struct thread_args {
    uint32_t* futex_addr;
    int op;
    _Atomic(bool) ready;
};

static void* thread_func(void* arg) {
    struct thread_args* args = arg;
    args->ready = true;
    ASSERT_OK(futex(args->futex_addr, args->op, 0, NULL, NULL, 0));
    return NULL;
}

int main(void) {
    ASSERT_ERRNO(futex_wait(NULL, 0, NULL), EFAULT);
    ASSERT_ERRNO(futex_wake(NULL, 0), EFAULT);

    {
        void* addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        ASSERT(addr != MAP_FAILED);

        void* futex_addr = (void*)ROUND_UP((uintptr_t)addr, sizeof(uint32_t));

        void* unaligned_addr = (unsigned char*)futex_addr + 1;
        ASSERT_ERRNO(futex_wait(unaligned_addr, 0, NULL), EINVAL);
        ASSERT_ERRNO(futex_wake(unaligned_addr, 0), EINVAL);

        struct timespec timeout = {.tv_nsec = 1000000};
        ASSERT_ERRNO(futex_wait(futex_addr, 0, &timeout), ETIMEDOUT);

        ASSERT_OK(munmap(addr, 4096));
    }

    {
        void* addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        ASSERT(addr != MAP_FAILED);
        void* futex_addr = (void*)ROUND_UP((uintptr_t)addr, sizeof(uint32_t));
        ASSERT_ERRNO(futex_wait(futex_addr, 1, NULL), EAGAIN);

        int pipefd[2];
        ASSERT_OK(pipe(pipefd));

        pid_t pid = ASSERT_OK(fork());
        if (pid == 0) {
            ASSERT_OK(write_all(pipefd[1], "x", 1));
            ASSERT_OK(futex_wait(futex_addr, 0, NULL));
            _exit(EXIT_SUCCESS);
        }

        char x;
        ASSERT_OK(read_exact(pipefd[0], &x, 1));
        wake_one(futex_addr, FUTEX_WAKE);

        int status;
        ASSERT_OK(waitpid(pid, &status, 0));
        ASSERT(WIFEXITED(status));
        ASSERT(WEXITSTATUS(status) == EXIT_SUCCESS);

        ASSERT_OK(munmap(addr, 4096));
    }

    {
        void* addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        ASSERT(addr != MAP_FAILED);
        void* futex_addr = (void*)ROUND_UP((uintptr_t)addr, sizeof(uint32_t));
        ASSERT_ERRNO(futex_wait(futex_addr, 1, NULL), EAGAIN);

        pthread_t thread;
        struct thread_args args = {
            .futex_addr = futex_addr,
            .op = FUTEX_WAIT,
            .ready = false,
        };
        ASSERT(pthread_create(&thread, NULL, thread_func, &args) == 0);
        while (!args.ready)
            usleep(1000);
        wake_one(futex_addr, FUTEX_WAKE);
        ASSERT(pthread_join(thread, NULL) == 0);

        ASSERT_OK(munmap(addr, 4096));
    }

    {
        void* addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        ASSERT(addr != MAP_FAILED);
        void* futex_addr = (void*)ROUND_UP((uintptr_t)addr, sizeof(uint32_t));
        ASSERT_ERRNO(futex_wait(futex_addr, 1, NULL), EAGAIN);

        pthread_t thread;
        struct thread_args args = {
            .futex_addr = futex_addr,
            .op = FUTEX_WAIT_PRIVATE,
            .ready = false,
        };
        ASSERT(pthread_create(&thread, NULL, thread_func, &args) == 0);
        while (!args.ready)
            usleep(1000);
        wake_one(futex_addr, FUTEX_WAKE_PRIVATE);
        ASSERT(pthread_join(thread, NULL) == 0);

        ASSERT_OK(munmap(addr, 4096));
    }

    return EXIT_SUCCESS;
}
