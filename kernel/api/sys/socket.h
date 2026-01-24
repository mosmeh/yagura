#pragma once

#include <common/stdint.h>

#define AF_UNSPEC 0
#define AF_UNIX 1        // Unix domain sockets
#define AF_LOCAL AF_UNIX // POSIX name for AF_UNIX

#define PF_UNSPEC AF_UNSPEC
#define PF_UNIX AF_UNIX
#define PF_LOCAL AF_LOCAL

#define SOCK_STREAM 1 // Sequenced, reliable, connection-based byte streams.
#define SOCK_NONBLOCK 00004000 // Atomically mark descriptor(s) as non-blocking.

enum { SHUT_RD, SHUT_WR, SHUT_RDWR };

typedef uint16_t sa_family_t;
typedef uint32_t socklen_t;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};
