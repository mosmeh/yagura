#include "sched.h"
#include "errno.h"
#include <private.h>
#include <stdarg.h>
#include <sys/types.h>

int clone(int (*fn)(void*), void* stack, int flags, void* arg, ...) {
    if (!fn || !stack)
        return -EINVAL;

    pid_t* parent_tid = NULL;
    void* tls = NULL;

    va_list ap;
    va_start(ap, arg);
    if (flags & (CLONE_PARENT_SETTID | CLONE_SETTLS))
        parent_tid = va_arg(ap, pid_t*);
    if (flags & CLONE_SETTLS)
        tls = va_arg(ap, void*);
    va_end(ap);

    return __syscall_return(
                      __clone(fn, stack, flags, arg, parent_tid, tls, NULL));
}

int sched_yield(void) { return __syscall_return(SYSCALL0(sched_yield)); }

int getcpu(unsigned int* cpu, unsigned int* node) {
    return __syscall_return(SYSCALL3(getcpu, cpu, node, NULL));
}
