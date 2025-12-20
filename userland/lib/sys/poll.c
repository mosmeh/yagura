#include "../private.h"
#include <sys/poll.h>

int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
    return __syscall_return(SYSCALL3(poll, fds, nfds, timeout));
}
