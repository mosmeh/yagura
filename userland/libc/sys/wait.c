#include "../private.h"
#include <common/macros.h>
#include <err.h>
#include <kernel/api/sys/resource.h>
#include <sys/resource.h>
#include <sys/wait.h>

pid_t wait(int* wstatus) { return waitpid(-1, wstatus, 0); }

pid_t waitpid(pid_t pid, int* wstatus, int options) {
    return wait4(pid, wstatus, options, NULL);
}

static void linux_rusage_to_rusage(const struct linux_rusage* linux_rusage,
                                   struct rusage* rusage) {
    *rusage = (struct rusage){
        .ru_maxrss = linux_rusage->ru_maxrss,
        .ru_ixrss = linux_rusage->ru_ixrss,
        .ru_idrss = linux_rusage->ru_idrss,
        .ru_isrss = linux_rusage->ru_isrss,
        .ru_minflt = linux_rusage->ru_minflt,
        .ru_majflt = linux_rusage->ru_majflt,
        .ru_nswap = linux_rusage->ru_nswap,
        .ru_inblock = linux_rusage->ru_inblock,
        .ru_oublock = linux_rusage->ru_oublock,
        .ru_msgsnd = linux_rusage->ru_msgsnd,
        .ru_msgrcv = linux_rusage->ru_msgrcv,
        .ru_nsignals = linux_rusage->ru_nsignals,
        .ru_nvcsw = linux_rusage->ru_nvcsw,
        .ru_nivcsw = linux_rusage->ru_nivcsw,
    };
    __linux_timeval_to_timeval(&linux_rusage->ru_utime, &rusage->ru_utime);
    __linux_timeval_to_timeval(&linux_rusage->ru_stime, &rusage->ru_stime);
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
        linux_rusage_to_rusage(&linux_rusage, rusage);
    return rc;
}
