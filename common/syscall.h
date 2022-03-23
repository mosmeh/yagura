#pragma once

#include <common/types.h>
#include <stddef.h>

#define SYSCALL_VECTOR 0x81

#define NUM_SYSCALLS SYS_LAST
enum syscall {
    SYS_EXIT,
    SYS_FORK,
    SYS_GETPID,
    SYS_YIELD,
    SYS_HALT,
    SYS_MMAP,
    SYS_PUTS,
    SYS_OPEN,
    SYS_CLOSE,
    SYS_READ,
    SYS_WRITE,
    SYS_LAST
};

#define PROT_EXEC 0x1
#define PROT_READ 0x2
#define PROT_WRITE 0x4
#define PROT_NONE 0

#define MAP_SHARED 1
#define MAP_PRIVATE 2

#define MAP_ANONYMOUS 0x4
#define MAP_ANON MAP_ANONYMOUS

typedef struct mmap_params {
    void* addr;
    size_t length;
    int prot;
    int flags;
    int fd;
    off_t offset;
} mmap_params;

typedef struct rw_params {
    int fd;
    void* buf;
    size_t count;
} rw_params;
