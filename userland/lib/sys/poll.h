#pragma once

#include <kernel/api/sys/poll.h>

int poll(struct pollfd* fds, nfds_t nfds, int timeout);
