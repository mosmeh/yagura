#include "../private.h"
#include <sys/select.h>

int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
           struct timeval* timeout) {
    struct linux_timeval linux_timeout;
    if (timeout) {
        linux_timeout.tv_sec = timeout->tv_sec;
        linux_timeout.tv_usec = timeout->tv_usec;
    }
    int rc = SYSCALL5(_newselect, nfds, readfds, writefds, exceptfds,
                      timeout ? &linux_timeout : NULL);
    if (timeout) {
        // Update the timeout regardless of whether the syscall was successful.
        timeout->tv_sec = linux_timeout.tv_sec;
        timeout->tv_usec = linux_timeout.tv_usec;
    }
    return __syscall_return(rc);
}

int pselect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
            const struct timespec* timeout, const sigset_t* sigmask) {
    // The syscall may modify the timeout, so we need to make a copy.
    struct timespec copied_timeout;
    if (timeout)
        copied_timeout = *timeout;
    return __syscall_return(
        SYSCALL6(pselect6, nfds, readfds, writefds, exceptfds,
                 timeout ? &copied_timeout : NULL, sigmask));
}
