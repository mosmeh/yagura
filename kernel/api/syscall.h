#pragma once

#include "types.h"
#include <stddef.h>

#define SYSCALL_VECTOR 0x81

#define ENUMERATE_SYSCALLS(F)                                                  \
    F(exit)                                                                    \
    F(fork)                                                                    \
    F(getpid)                                                                  \
    F(yield)                                                                   \
    F(halt)                                                                    \
    F(mmap)                                                                    \
    F(puts)                                                                    \
    F(open)                                                                    \
    F(close)                                                                   \
    F(read)                                                                    \
    F(write)                                                                   \
    F(ioctl)                                                                   \
    F(getdents)                                                                \
    F(socket)                                                                  \
    F(bind)                                                                    \
    F(listen)                                                                  \
    F(accept)                                                                  \
    F(connect)

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
