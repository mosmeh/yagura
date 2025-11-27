#include "time.h"
#include <err.h>
#include <errno.h>
#include <private.h>

int gettimeofday(struct timeval* tv, struct timezone* tz) {
    (void)tz;
    struct linux_timeval linux_tv;
    int rc = SYSCALL2(gettimeofday, &linux_tv, NULL);
    if (IS_ERR(rc)) {
        errno = -rc;
        return -1;
    }
    tv->tv_sec = linux_tv.tv_sec;
    tv->tv_usec = linux_tv.tv_usec;
    return 0;
}

int settimeofday(const struct timeval* tv, const struct timezone* tz) {
    (void)tz;
    struct linux_timeval linux_tv = {
        .tv_sec = tv->tv_sec,
        .tv_usec = tv->tv_usec,
    };
    return __syscall_return(SYSCALL2(settimeofday, &linux_tv, NULL));
}
