#pragma once

#include <kernel/api/signal.h>
#include <kernel/api/time.h>
#include <sys/time.h>

#define FD_SETSIZE 1024
#define __NFDBITS (8 * sizeof(long))

typedef struct {
    unsigned long fds_bits[FD_SETSIZE / __NFDBITS];
} fd_set;

#define FD_CLR(fd, set)                                                        \
    ((set)->fds_bits[(fd) / __NFDBITS] &= ~(1UL << ((fd) % __NFDBITS)))

#define FD_SET(fd, set)                                                        \
    ((set)->fds_bits[(fd) / __NFDBITS] |= (1UL << ((fd) % __NFDBITS)))

#define FD_ISSET(fd, set)                                                      \
    ((set)->fds_bits[(fd) / __NFDBITS] & (1UL << ((fd) % __NFDBITS)))

#define FD_ZERO(set)                                                           \
    do {                                                                       \
        fd_set* __set = (set);                                                 \
        for (unsigned int __i = 0;                                             \
             __i < sizeof(__set) / sizeof(__set->fds_bits[0]); ++__i)          \
            __set->fds_bits[__i] = 0;                                          \
    } while (0)

int select(int nfds, fd_set* restrict readfds, fd_set* restrict writefds,
           fd_set* restrict exceptfds, struct timeval* restrict timeout);

int pselect(int nfds, fd_set* restrict readfds, fd_set* restrict writefds,
            fd_set* restrict exceptfds, const struct timespec* restrict timeout,
            const sigset_t* restrict sigmask);
