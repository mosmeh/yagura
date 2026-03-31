#include "../private.h"
#include <common/macros.h>
#include <err.h>
#include <kernel/api/sys/resource.h>
#include <sys/wait.h>

pid_t wait(int* wstatus) { return waitpid(-1, wstatus, 0); }

pid_t waitpid(pid_t pid, int* wstatus, int options) {
    return wait4(pid, wstatus, options, NULL);
}

NODISCARD static pid_t raw_wait4(pid_t pid, int* wstatus, int options,
                                 struct linux_rusage* rusage) {
    return SYSCALL4(wait4, pid, wstatus, options, rusage);
}

pid_t wait4(pid_t pid, int* wstatus, int options, struct rusage* rusage) {
    struct linux_rusage linux_rusage;
    pid_t rc = raw_wait4(pid, wstatus, options, rusage ? &linux_rusage : NULL);
    if (IS_ERR(rc))
        return __syscall_return(rc);
    if (rc > 0 && rusage) // rusage is not written when rc = 0 (WNOHANG)
        __linux_rusage_to_rusage(&linux_rusage, rusage);
    return rc;
}
