#include "poll.h"
#include <private.h>

int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
    RETURN_WITH_ERRNO(int, SYSCALL3(poll, fds, nfds, timeout));
}
