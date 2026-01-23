#pragma once

struct linux_timeval {
    long tv_sec;
    long tv_usec;
};

struct timezone {
    int tz_minuteswest; /* minutes west of Greenwich */
    int tz_dsttime;     /* type of DST correction */
};
