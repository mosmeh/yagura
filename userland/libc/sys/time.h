#pragma once

#include <kernel/api/sys/time.h>
#include <sys/types.h>

struct timeval {
    time_t tv_sec;       /* seconds */
    suseconds_t tv_usec; /* microseconds */
};

int gettimeofday(struct timeval* restrict tv, struct timezone* restrict tz);
int settimeofday(const struct timeval* tv, const struct timezone* tz);
