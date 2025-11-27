#include "poll.h"
#include <private.h>

int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
    return __syscall_return(SYSCALL3(poll, fds, nfds, timeout));
}
