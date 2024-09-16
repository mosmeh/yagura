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

typedef int32_t time32_t;

struct timespec32 {
    time32_t tv_sec;
    int32_t tv_nsec;
};
