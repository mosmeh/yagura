#pragma once

#include <kernel/api/signal.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/time.h>

int poll(struct pollfd* fds, nfds_t nfds, int timeout);

int ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p,
          const sigset_t* sigmask);
