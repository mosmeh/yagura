#include "sched.h"
#include <private.h>
#include <stdarg.h>
#include <sys/types.h>

int clone(int (*fn)(void*), void* stack, int flags, void* arg, ...) {
    if (!fn || !stack)
        return -EINVAL;

    pid_t* parent_tid = NULL;
    void* tls = NULL;
    pid_t* child_tid = NULL;

    int va_flags = flags & (CLONE_PARENT_SETTID | CLONE_SETTLS |
                            CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID);
    va_list ap;
    va_start(ap, arg);

    if (va_flags)
        parent_tid = va_arg(ap, pid_t*);
    va_flags &= ~CLONE_PARENT_SETTID;

    if (va_flags)
        tls = va_arg(ap, void*);
    va_flags &= ~CLONE_SETTLS;

    if (va_flags)
        child_tid = va_arg(ap, pid_t*);

    va_end(ap);

    RETURN_WITH_ERRNO(
        int, __clone(fn, stack, flags, arg, parent_tid, tls, child_tid));
}

int sched_yield(void) { RETURN_WITH_ERRNO(int, SYSCALL0(sched_yield)); }

int getcpu(unsigned int* cpu, unsigned int* node) {
    RETURN_WITH_ERRNO(int, SYSCALL3(getcpu, cpu, node, NULL));
}
