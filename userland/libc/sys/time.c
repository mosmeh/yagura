#include "../private.h"
#include <err.h>
#include <errno.h>
#include <sys/time.h>

void __linux_timeval_to_timeval(const struct linux_timeval* linux_tv,
                                struct timeval* tv) {
    *tv = (struct timeval){
        .tv_sec = linux_tv->tv_sec,
        .tv_usec = linux_tv->tv_usec,
    };
}

void __timeval_to_linux_timeval(const struct timeval* tv,
                                struct linux_timeval* linux_tv) {
    *linux_tv = (struct linux_timeval){
        .tv_sec = tv->tv_sec,
        .tv_usec = tv->tv_usec,
    };
}

int gettimeofday(struct timeval* tv, struct timezone* tz) {
    struct linux_timeval linux_tv;
    int rc = SYSCALL2(gettimeofday, tv ? &linux_tv : NULL, tz);
    if (IS_ERR(rc)) {
        errno = -rc;
        return -1;
    }
    if (tv)
        __linux_timeval_to_timeval(&linux_tv, tv);
    return 0;
}

int settimeofday(const struct timeval* tv, const struct timezone* tz) {
    struct linux_timeval linux_tv;
    if (tv)
        __timeval_to_linux_timeval(tv, &linux_tv);
    return __syscall_return(SYSCALL2(settimeofday, tv ? &linux_tv : NULL, tz));
}
