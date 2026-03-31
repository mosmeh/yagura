#include "../private.h"
#include <common/macros.h>
#include <sys/resource.h>

void __linux_rusage_to_rusage(const struct linux_rusage* linux_rusage,
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

NODISCARD static int raw_getrusage(int who, struct linux_rusage* user_usage) {
    return __syscall_return(SYSCALL2(getrusage, who, user_usage));
}

int getrusage(int who, struct rusage* usage) {
    struct linux_rusage linux_usage;
    if (raw_getrusage(who, usage ? &linux_usage : NULL) < 0)
        return -1;
    if (usage)
        __linux_rusage_to_rusage(&linux_usage, usage);
    return 0;
}
