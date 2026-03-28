#include "private.h"
#include <common/macros.h>
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>

int clone(int (*fn)(void*), void* stack, int flags, void* arg, ...) {
    if (!fn || !stack)
        return __syscall_return(-EINVAL);

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
        __clone(fn, stack, flags, arg, parent_tid, NULL, tls));
}

int unshare(int flags) { return __syscall_return(SYSCALL1(unshare, flags)); }

NODISCARD static ssize_t raw_sched_getaffinity(pid_t pid, size_t cpusetsize,
                                               cpu_set_t* mask) {
    return SYSCALL3(sched_getaffinity, pid, cpusetsize, mask);
}

int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t* mask) {
    ssize_t nbytes = raw_sched_getaffinity(pid, cpusetsize, mask);
    if (IS_ERR(nbytes))
        return __syscall_return(nbytes);
    if ((size_t)nbytes < cpusetsize)
        memset((unsigned char*)mask + nbytes, 0, cpusetsize - nbytes);
    return 0;
}

int sched_yield(void) { return __syscall_return(SYSCALL0(sched_yield)); }

int getcpu(unsigned int* cpu, unsigned int* node) {
    return __syscall_return(SYSCALL3(getcpu, cpu, node, NULL));
}
