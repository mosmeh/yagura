#pragma once

#include <kernel/api/time.h>

#define CLOCKS_PER_SEC 1000000

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

clock_t clock(void);

time_t time(time_t* tloc);
int stime(const time_t* t);

double difftime(time_t time1, time_t time0);

struct tm* gmtime_r(time_t const* t, struct tm* tm);
char* asctime_r(const struct tm* time_ptr, char* buf);

int nanosleep(const struct timespec* req, struct timespec* rem);

int clock_gettime(clockid_t clockid, struct timespec* tp);
int clock_settime(clockid_t clockid, const struct timespec* tp);
int clock_getres(clockid_t clockid, struct timespec* res);
int clock_nanosleep(clockid_t clockid, int flags,
                    const struct timespec* request, struct timespec* remain);
