#pragma once

#include <common/stdint.h>

#define AF_UNIX 1
#define AF_LOCAL AF_UNIX

#define SOCK_STREAM 1

enum { SHUT_RD, SHUT_WR, SHUT_RDWR };

typedef uint16_t sa_family_t;
typedef uint32_t socklen_t;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};
