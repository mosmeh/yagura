#pragma once

#include "types.h"
#include <stddef.h>

#define SYSCALL_VECTOR 0x81

#define ENUMERATE_SYSCALLS(F)                                                  \
    F(accept)                                                                  \
    F(bind)                                                                    \
    F(chdir)                                                                   \
    F(clock_gettime)                                                           \
    F(clock_nanosleep)                                                         \
    F(close)                                                                   \
    F(connect)                                                                 \
    F(dbgprint)                                                                \
    F(dup2)                                                                    \
    F(execve)                                                                  \
    F(exit)                                                                    \
    F(fcntl)                                                                   \
    F(fork)                                                                    \
    F(ftruncate)                                                               \
    F(getcwd)                                                                  \
    F(getdents)                                                                \
    F(getpgid)                                                                 \
    F(getpid)                                                                  \
    F(ioctl)                                                                   \
    F(kill)                                                                    \
    F(link)                                                                    \
    F(listen)                                                                  \
    F(lseek)                                                                   \
    F(lstat)                                                                   \
    F(mkdir)                                                                   \
    F(mknod)                                                                   \
    F(mmap)                                                                    \
    F(mount)                                                                   \
    F(munmap)                                                                  \
    F(open)                                                                    \
    F(pipe)                                                                    \
    F(poll)                                                                    \
    F(read)                                                                    \
    F(readlink)                                                                \
    F(reboot)                                                                  \
    F(rename)                                                                  \
    F(rmdir)                                                                   \
    F(sched_yield)                                                             \
    F(setpgid)                                                                 \
    F(shutdown)                                                                \
    F(socket)                                                                  \
    F(stat)                                                                    \
    F(symlink)                                                                 \
    F(sysconf)                                                                 \
    F(times)                                                                   \
    F(uname)                                                                   \
    F(unlink)                                                                  \
    F(waitpid)                                                                 \
    F(write)

enum {
#define DEFINE_ITEM(name) SYS_##name,
    ENUMERATE_SYSCALLS(DEFINE_ITEM)
#undef DEFINE_ITEM
        NUM_SYSCALLS
};

struct mmap_params {
    void* addr;
    size_t length;
    int prot;
    int flags;
    int fd;
    off_t offset;
};

struct mount_params {
    const char* source;
    const char* target;
    const char* filesystemtype;
    unsigned long mountflags;
    const void* data;
};
