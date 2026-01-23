#include "../private.h"
#include <err.h>
#include <errno.h>
#include <sys/time.h>

int gettimeofday(struct timeval* tv, struct timezone* tz) {
    struct linux_timeval linux_tv;
    int rc = SYSCALL2(gettimeofday, tv ? &linux_tv : NULL, tz);
    if (IS_ERR(rc)) {
        errno = -rc;
        return -1;
    }
    if (tv) {
        tv->tv_sec = linux_tv.tv_sec;
        tv->tv_usec = linux_tv.tv_usec;
    }
    return 0;
}

int settimeofday(const struct timeval* tv, const struct timezone* tz) {
    struct linux_timeval linux_tv;
    if (tv) {
        linux_tv = (struct linux_timeval){
            .tv_sec = tv->tv_sec,
            .tv_usec = tv->tv_usec,
        };
    }
    return __syscall_return(SYSCALL2(settimeofday, tv ? &linux_tv : NULL, tz));
}
