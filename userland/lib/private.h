#pragma once

#include "errno.h"
#include <err.h>
#include <sys/types.h>
#include <syscall.h>

extern size_t __tls_size;
struct pthread* __init_tls(void* tls);

struct pthread {
    struct pthread* self;
    volatile atomic_uint state;
    void* alloc_base;
    void* (*fn)(void*);
    void* arg;
    pid_t tid;
    void* retval;
};

int syscall(int num, int, int, int, int, int, int);

#define SYSCALL0(name) SYSCALL1(name, 0)
#define SYSCALL1(name, arg1) SYSCALL2(name, arg1, 0)
#define SYSCALL2(name, arg1, arg2) SYSCALL3(name, arg1, arg2, 0)
#define SYSCALL3(name, arg1, arg2, arg3) SYSCALL4(name, arg1, arg2, arg3, 0)
#define SYSCALL4(name, arg1, arg2, arg3, arg4)                                 \
    SYSCALL5(name, arg1, arg2, arg3, arg4, 0)
#define SYSCALL5(name, arg1, arg2, arg3, arg4, arg5)                           \
    SYSCALL6(name, arg1, arg2, arg3, arg4, arg5, 0)
#define SYSCALL6(name, arg1, arg2, arg3, arg4, arg5, arg6)                     \
    syscall(SYS_##name, (int)(arg1), (int)(arg2), (int)(arg3), (int)(arg4),    \
            (int)(arg5), (int)(arg6))

#define RETURN_WITH_ERRNO(type, rc)                                            \
    do {                                                                       \
        int __rc = (rc);                                                       \
        if (IS_ERR(__rc)) {                                                    \
            errno = -__rc;                                                     \
            return (type)(-1);                                                 \
        }                                                                      \
        return (type)__rc;                                                     \
    } while (0)

int __clone(int (*fn)(void*), void* stack, int flags, void* arg,
            pid_t* parent_tid, void* tls, pid_t* child_tid);
