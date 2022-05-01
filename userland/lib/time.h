#pragma once

#include <kernel/api/time.h>

int nanosleep(const struct timespec* req, struct timespec* rem);

clock_t clock(void);

time_t time(time_t* tloc);
int clock_gettime(clockid_t clk_id, struct timespec* tp);

struct tm* gmtime_r(time_t const* t, struct tm* tm);
char* asctime_r(const struct tm* time_ptr, char* buf);
