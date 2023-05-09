#pragma once

#define POLLIN (1 << 0)
#define POLLPRI (1 << 1)
#define POLLOUT (1 << 2)
#define POLLERR (1 << 3)
#define POLLHUP (1 << 4)
#define POLLNVAL (1 << 5)

typedef unsigned nfds_t;

struct pollfd {
    int fd;
    short events;
    short revents;
};
