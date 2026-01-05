#pragma once

#include <stdatomic.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/types.h>

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

long syscall(long num, long, long, long, long, long, long);

#define SYSCALL0(name) SYSCALL1(name, 0)
#define SYSCALL1(name, arg1) SYSCALL2(name, arg1, 0)
#define SYSCALL2(name, arg1, arg2) SYSCALL3(name, arg1, arg2, 0)
#define SYSCALL3(name, arg1, arg2, arg3) SYSCALL4(name, arg1, arg2, arg3, 0)
#define SYSCALL4(name, arg1, arg2, arg3, arg4)                                 \
    SYSCALL5(name, arg1, arg2, arg3, arg4, 0)
#define SYSCALL5(name, arg1, arg2, arg3, arg4, arg5)                           \
    SYSCALL6(name, arg1, arg2, arg3, arg4, arg5, 0)
#define SYSCALL6(name, arg1, arg2, arg3, arg4, arg5, arg6)                     \
    syscall(SYS_##name, (long)(arg1), (long)(arg2), (long)(arg3),              \
            (long)(arg4), (long)(arg5), (long)(arg6))

unsigned long __syscall_return(unsigned long rc);

int __clone(int (*fn)(void*), void* stack, int flags, void* arg,
            pid_t* parent_tid, void* tls, pid_t* child_tid);
