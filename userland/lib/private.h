#pragma once

#include "errno.h"
#include <kernel/api/err.h>
#include <kernel/api/sys/syscall.h>

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
        int _rc = (rc);                                                        \
        if (IS_ERR(_rc)) {                                                     \
            errno = -(_rc);                                                    \
            return (type)(-1);                                                 \
        }                                                                      \
        return (type)(_rc);                                                    \
    } while (0);
