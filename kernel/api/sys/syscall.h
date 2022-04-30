#pragma once

#include "types.h"
#include <stddef.h>

#define SYSCALL_VECTOR 0x81

#define ENUMERATE_SYSCALLS(F)                                                  \
    F(accept)                                                                  \
    F(bind)                                                                    \
    F(chdir)                                                                   \
    F(clock_gettime)                                                           \
    F(close)                                                                   \
    F(connect)                                                                 \
    F(dbgputs)                                                                 \
    F(dup)                                                                     \
    F(dup2)                                                                    \
    F(execve)                                                                  \
    F(exit)                                                                    \
    F(fork)                                                                    \
    F(ftruncate)                                                               \
    F(getcwd)                                                                  \
    F(getdents)                                                                \
    F(getpgid)                                                                 \
    F(getpid)                                                                  \
    F(ioctl)                                                                   \
    F(kill)                                                                    \
    F(listen)                                                                  \
    F(mkdir)                                                                   \
    F(mknod)                                                                   \
    F(mmap)                                                                    \
    F(munmap)                                                                  \
    F(nanosleep)                                                               \
    F(open)                                                                    \
    F(pipe)                                                                    \
    F(read)                                                                    \
    F(reboot)                                                                  \
    F(sched_yield)                                                             \
    F(setpgid)                                                                 \
    F(socket)                                                                  \
    F(stat)                                                                    \
    F(sysconf)                                                                 \
    F(times)                                                                   \
    F(waitpid)                                                                 \
    F(write)

enum {
#define DEFINE_ITEM(name) SYS_##name,
    ENUMERATE_SYSCALLS(DEFINE_ITEM)
#undef DEFINE_ITEM
        NUM_SYSCALLS
};

typedef struct mmap_params {
    void* addr;
    size_t length;
    int prot;
    int flags;
    int fd;
    off_t offset;
} mmap_params;
