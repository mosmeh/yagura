#include "private.h"
#include <common/calendar.h>
#include <err.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <sys/times.h>
#include <time.h>

clock_t clock(void) {
    struct tms tms;
    times(&tms);
    uint64_t ticks = (uint64_t)tms.tms_utime + tms.tms_stime;
    return ticks * CLOCKS_PER_SEC / getauxval(AT_CLKTCK);
}

time_t time(time_t* tloc) {
    struct timespec tp;
    if (clock_gettime(CLOCK_REALTIME, &tp) < 0)
        return -1;
    if (tloc)
        *tloc = tp.tv_sec;
    return tp.tv_sec;
}

int stime(const time_t* t) {
    struct timespec tp = {.tv_sec = *t};
    return clock_settime(CLOCK_REALTIME, &tp);
}

double difftime(time_t time1, time_t time0) { return (double)(time1 - time0); }

struct tm* gmtime_r(const time_t* t, struct tm* tm) {
    static int const seconds_per_day = 60 * 60 * 24;

    time_t time = *t;

    unsigned year = 1970;
    for (;; ++year) {
        time_t seconds_in_this_year =
            (time_t)days_in_year(year) * seconds_per_day;
        if (time < seconds_in_this_year)
            break;
        time -= seconds_in_this_year;
    }
    tm->tm_year = year - 1900;

    time_t days = time / seconds_per_day;
    tm->tm_yday = days;

    time_t seconds = time % seconds_per_day;
    tm->tm_sec = seconds % 60;

    time_t minutes = seconds / 60;
    tm->tm_hour = minutes / 60;
    tm->tm_min = minutes % 60;

    unsigned month;
    for (month = 1; month < 12; ++month) {
        time_t days_in_this_month = (time_t)days_in_month(year, month);
        if (days < days_in_this_month)
            break;
        days -= days_in_this_month;
    }

    tm->tm_mon = month - 1;
    tm->tm_mday = days + 1;
    tm->tm_wday = day_of_week(year, month, tm->tm_mday);

    return tm;
}

char* asctime_r(const struct tm* time_ptr, char* buf) {
    static const char* day_names[] = {"Sun", "Mon", "Tue", "Wed",
                                      "Thu", "Fri", "Sat"};
    static const char* month_names[] = {"Jan", "Feb", "Mar", "Apr",
                                        "May", "Jun", "Jul", "Aug",
                                        "Sep", "Oct", "Nov", "Dec"};
    int len = sprintf(
        buf, "%s %s %2d %02d:%02d:%02d %d", day_names[time_ptr->tm_wday],
        month_names[time_ptr->tm_mon], time_ptr->tm_mday, time_ptr->tm_hour,
        time_ptr->tm_min, time_ptr->tm_sec, time_ptr->tm_year + 1900);
    return len > 0 ? buf : NULL;
}

#ifdef SYS_clock_gettime64
#undef SYS_clock_gettime
#define SYS_clock_gettime SYS_clock_gettime64
#endif

int clock_gettime(clockid_t clockid, struct timespec* tp) {
    return __syscall_return(SYSCALL2(clock_gettime, clockid, tp));
}

#ifdef SYS_clock_settime64
#undef SYS_clock_settime
#define SYS_clock_settime SYS_clock_settime64
#endif

int clock_settime(clockid_t clockid, const struct timespec* tp) {
    return __syscall_return(SYSCALL2(clock_settime, clockid, tp));
}

#ifdef SYS_clock_getres_time64
#undef SYS_clock_getres
#define SYS_clock_getres SYS_clock_getres_time64
#endif

int clock_getres(clockid_t clockid, struct timespec* res) {
    return __syscall_return(SYSCALL2(clock_getres, clockid, res));
}

#ifdef SYS_clock_nanosleep_time64
#undef SYS_clock_nanosleep
#define SYS_clock_nanosleep SYS_clock_nanosleep_time64
#endif

NODISCARD static int raw_clock_nanosleep(clockid_t clockid, int flags,
                                         const struct timespec* request,
                                         struct timespec* remain) {
    return SYSCALL4(clock_nanosleep, clockid, flags, request, remain);
}

int nanosleep(const struct timespec* req, struct timespec* rem) {
    return __syscall_return(raw_clock_nanosleep(CLOCK_MONOTONIC, 0, req, rem));
}

int clock_nanosleep(clockid_t clockid, int flags,
                    const struct timespec* request, struct timespec* remain) {
    int rc = raw_clock_nanosleep(clockid, flags, request, remain);
    // unlike other syscall wrappers, clock_nanosleep returns the error value
    // instead of returning -1 and setting errno
    if (IS_ERR(rc))
        return -rc;
    return 0;
}
