#include "../private.h"
#include <sys/select.h>

#ifdef SYS__newselect
#undef SYS_select
#define SYS_select SYS__newselect
#endif

int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
           struct timeval* timeout) {
    struct linux_timeval linux_timeout;
    if (timeout) {
        linux_timeout.tv_sec = timeout->tv_sec;
        linux_timeout.tv_usec = timeout->tv_usec;
    }
    int rc = SYSCALL5(select, nfds, readfds, writefds, exceptfds,
                      timeout ? &linux_timeout : NULL);
    if (timeout) {
        // Update the timeout regardless of whether the syscall was successful.
        timeout->tv_sec = linux_timeout.tv_sec;
        timeout->tv_usec = linux_timeout.tv_usec;
    }
    return __syscall_return(rc);
}

#ifdef SYS_pselect6_time64
#undef SYS_pselect6
#define SYS_pselect6 SYS_pselect6_time64
#endif

int pselect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
            const struct timespec* timeout, const sigset_t* sigmask) {
    // The syscall may modify the timeout, so we need to make a copy.
    struct timespec copied_timeout;
    if (timeout)
        copied_timeout = *timeout;
    unsigned long sigset[] = {(uintptr_t)sigmask, sizeof(sigset_t)};
    return __syscall_return(
        SYSCALL6(pselect6, nfds, readfds, writefds, exceptfds,
                 timeout ? &copied_timeout : NULL, sigmask ? sigset : NULL));
}
