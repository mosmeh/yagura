#include "../private.h"
#include <sys/poll.h>

int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
    return __syscall_return(SYSCALL3(poll, fds, nfds, timeout));
}

#ifdef SYS_ppoll_time64
#undef SYS_ppoll
#define SYS_ppoll SYS_ppoll_time64
#endif

int ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p,
          const sigset_t* sigmask) {
    // The syscall may modify the timeout, so we need to make a copy.
    struct timespec timeout;
    if (tmo_p)
        timeout = *tmo_p;
    return __syscall_return(SYSCALL5(ppoll, fds, nfds, tmo_p ? &timeout : NULL,
                                     sigmask, sizeof(sigset_t)));
}
