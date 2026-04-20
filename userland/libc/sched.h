#pragma once

#include <kernel/api/sched.h>
#include <kernel/api/sys/types.h>
#include <stddef.h>

int clone(int (*fn)(void*), void* stack, int flags, void* arg, ...
          /* pid_t* parent_tid, void* tls, pid_t* child_tid */);

int unshare(int flags);

#define __CPU_SET_SIZE 1024
#define __CPU_BITS (8 * sizeof(unsigned long))

typedef struct {
    unsigned long __bits[__CPU_SET_SIZE / __CPU_BITS];
} cpu_set_t;

#define __CPU_INDEX(cpu) ((cpu) / __CPU_BITS)
#define __CPU_MASK(cpu) (1UL << ((cpu) % __CPU_BITS))

#define CPU_ZERO(set)                                                          \
    do {                                                                       \
        cpu_set_t* __set = (set);                                              \
        for (unsigned int __i = 0;                                             \
             __i < sizeof(__set->__bits) / sizeof(__set->__bits[0]); ++__i)    \
            __set->__bits[__i] = 0;                                            \
    } while (0)

#define CPU_SET(cpu, set) ((set)->__bits[__CPU_INDEX(cpu)] |= __CPU_MASK(cpu))
#define CPU_CLR(cpu, set) ((set)->__bits[__CPU_INDEX(cpu)] &= ~__CPU_MASK(cpu))
#define CPU_ISSET(cpu, set) ((set)->__bits[__CPU_INDEX(cpu)] & __CPU_MASK(cpu))

#define CPU_COUNT(set)                                                         \
    ({                                                                         \
        const cpu_set_t* __set = (set);                                        \
        size_t __count = 0;                                                    \
        for (unsigned int __i = 0; __i < __CPU_SET_SIZE; ++__i)                \
            if (CPU_ISSET(__i, __set))                                         \
                ++__count;                                                     \
        __count;                                                               \
    })

int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t* mask);
int sched_yield(void);

int getcpu(unsigned int* cpu, unsigned int* node);
