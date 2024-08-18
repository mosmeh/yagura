#include "sched.h"
#include <private.h>

int __clone(int (*fn)(void*), void* stack, int flags, void* arg);

int clone(int (*fn)(void*), void* stack, int flags, void* arg, ...) {
    RETURN_WITH_ERRNO(int, __clone(fn, stack, flags, arg));
}

int sched_yield(void) { RETURN_WITH_ERRNO(int, SYSCALL0(sched_yield)); }
