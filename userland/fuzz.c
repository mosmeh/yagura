#include <common/random.h>
#include <common/stdbool.h>
#include <errno.h>
#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define NUM_SYSCALLS 1025

static const int denylist[] = {
    SYS_exit,          SYS_exit_group, SYS_pause,
#ifdef SYS_sigsuspend
    SYS_sigsuspend,
#endif
#ifdef SYS_rt_sigsuspend
    SYS_rt_sigsuspend,
#endif
};

static uint32_t random_state[4];

static void random_init(long seed) {
    uint64_t seed64 = seed;
    uint64_t a = splitmix64_next(&seed64);
    uint64_t b = splitmix64_next(&seed64);
    random_state[0] = a & 0xffffffff;
    random_state[1] = a >> 32;
    random_state[2] = b & 0xffffffff;
    random_state[3] = b >> 32;
}

static uint32_t random_next(void) {
    return xoshiro128plusplus_next(random_state);
}

int main(int argc, char** argv) {
    int num_iterations = (argc >= 2) ? atoi(argv[1]) : 1000;
    long seed = (argc >= 3) ? atoi(argv[2]) : time(NULL);
    printf("%s %d %ld\n", argv[0], num_iterations, seed);

    static const char* const str = "Hello, World!";
    int page_size = sysconf(_SC_PAGESIZE);

    unsigned long patterns[] = {
        0, // Generate random value
        0,
        1,
        (unsigned long)str,
        strlen(str),
        strlen(str) - 1,
        strlen(str) + 1,
        page_size,
        0xc0000000,
        0xc0000000 - page_size,
        0xffffffff,
    };

    bool allowed[NUM_SYSCALLS];
    for (size_t i = 0; i < NUM_SYSCALLS; ++i)
        allowed[i] = true;
    for (size_t i = 0; i < ARRAY_SIZE(denylist); ++i) {
        ASSERT(denylist[i] < NUM_SYSCALLS);
        allowed[denylist[i]] = false;
    }

    random_init(seed);

    for (int iter = 0; iter < num_iterations; ++iter) {
        int num;
        for (;;) {
            num = random_next() % NUM_SYSCALLS;
            if (allowed[num])
                break;
        }

        long args[6];
        for (size_t i = 0; i < ARRAY_SIZE(args); ++i) {
            size_t r = random_next() % ARRAY_SIZE(patterns);
            args[i] = r == 0 ? random_next() : patterns[r];
        }

        printf("syscall(%d, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx)\n", num,
               args[0], args[1], args[2], args[3], args[4], args[5]);
        long rc =
            syscall(num, args[0], args[1], args[2], args[3], args[4], args[5]);
        if (rc < 0 && errno == ENOSYS) {
            // Don't try unimplemented syscalls again
            allowed[num] = false;
        }
    }

    return EXIT_SUCCESS;
}
