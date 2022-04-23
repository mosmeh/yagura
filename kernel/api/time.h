#pragma once

#include "types.h"

#define CLOCKS_PER_SEC 250

enum { CLOCK_REALTIME, CLOCK_MONOTONIC };

typedef int clockid_t;

struct timespec {
    time_t tv_sec;
    long tv_nsec;
};
