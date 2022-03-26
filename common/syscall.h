#pragma once

#include <common/types.h>
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
    F(ioctl)

enum {
#define DEFINE_ITEM(name) SYS_##name,
    ENUMERATE_SYSCALLS(DEFINE_ITEM)
#undef DEFINE_ITEM
        NUM_SYSCALLS
};

#define PROT_READ 0x2
#define PROT_WRITE 0x4

#define MAP_SHARED 0x1
#define MAP_PRIVATE 0x2
#define MAP_ANONYMOUS 0x8
#define MAP_ANON MAP_ANONYMOUS

#define MAP_FAILED ((void*)-1)

typedef struct mmap_params {
    void* addr;
    size_t length;
    int prot;
    int flags;
    int fd;
    off_t offset;
} mmap_params;
