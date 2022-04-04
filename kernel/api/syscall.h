#pragma once

#include "types.h"
#include <stddef.h>

#define SYSCALL_VECTOR 0x81

#define ENUMERATE_SYSCALLS(F)                                                  \
    F(accept)                                                                  \
    F(bind)                                                                    \
    F(close)                                                                   \
    F(connect)                                                                 \
    F(execve)                                                                  \
    F(exit)                                                                    \
    F(fork)                                                                    \
    F(ftruncate)                                                               \
    F(getdents)                                                                \
    F(getpid)                                                                  \
    F(halt)                                                                    \
    F(ioctl)                                                                   \
    F(listen)                                                                  \
    F(mmap)                                                                    \
    F(nanosleep)                                                               \
    F(open)                                                                    \
    F(puts)                                                                    \
    F(read)                                                                    \
    F(socket)                                                                  \
    F(write)                                                                   \
    F(yield)

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
