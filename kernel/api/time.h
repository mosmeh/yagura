#pragma once

#include "sys/types.h"

#define TIMER_ABSTIME 1

enum {
    CLOCK_REALTIME,
    CLOCK_MONOTONIC,
};

typedef int clockid_t;

struct timespec {
    time_t tv_sec;
    long long tv_nsec;
};
