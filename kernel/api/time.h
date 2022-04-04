#pragma once

#include "types.h"

#define CLOCKS_PER_SEC 250

struct timespec {
    time_t tv_sec;
    long tv_nsec;
};
