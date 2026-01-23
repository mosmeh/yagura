#include <kernel/api/errno.h>
#include <kernel/api/sys/time.h>
#include <kernel/arch/system.h>
#include <kernel/lock.h>
#include <kernel/time.h>

void timespec_add(struct timespec* this, const struct timespec* other) {
    this->tv_sec += other->tv_sec;
    this->tv_nsec += other->tv_nsec;
    if (this->tv_nsec >= NANOS_PER_SEC) {
        ++this->tv_sec;
        this->tv_nsec -= NANOS_PER_SEC;
    }
}

void timespec_saturating_sub(struct timespec* this,
                             const struct timespec* other) {
    this->tv_sec -= other->tv_sec;
    this->tv_nsec -= other->tv_nsec;
    if (this->tv_nsec < 0) {
        --this->tv_sec;
        this->tv_nsec += NANOS_PER_SEC;
    }
    if (this->tv_sec < 0)
        this->tv_sec = this->tv_nsec = 0;
}

int timespec_compare(const struct timespec* a, const struct timespec* b) {
    if (a->tv_sec > b->tv_sec)
        return 1;
    if (a->tv_sec < b->tv_sec)
        return -1;
    if (a->tv_nsec > b->tv_nsec)
        return 1;
    if (a->tv_nsec < b->tv_nsec)
        return -1;
    return 0;
}

volatile _Atomic(unsigned long) uptime;
static struct timespec now;
static struct spinlock now_lock;

void time_init(void) { arch_time(&now); }

void time_tick(void) {
    ++uptime;

    SCOPED_LOCK(spinlock, &now_lock);
    now.tv_nsec += NANOS_PER_SEC / CLK_TCK;
    if (now.tv_nsec >= NANOS_PER_SEC) {
        ++now.tv_sec;
        now.tv_nsec -= NANOS_PER_SEC;
    }
}

int time_now(clockid_t clock_id, struct timespec* out_tp) {
    switch (clock_id) {
    case CLOCK_REALTIME: {
        if (out_tp) {
            SCOPED_LOCK(spinlock, &now_lock);
            *out_tp = now;
        }
        break;
    }
    case CLOCK_MONOTONIC: {
        if (out_tp) {
            unsigned long t = uptime;
            out_tp->tv_sec = t / CLK_TCK;
            out_tp->tv_nsec =
                ((uint64_t)t - (uint64_t)out_tp->tv_sec * CLK_TCK) *
                NANOS_PER_SEC / CLK_TCK;
        }
        break;
    }
    default:
        return -EINVAL;
    }
    return 0;
}

int time_set(clockid_t clock_id, const struct timespec* tp) {
    if (tp->tv_sec < 0 || tp->tv_nsec < 0 || tp->tv_nsec >= NANOS_PER_SEC)
        return -EINVAL;

    switch (clock_id) {
    case CLOCK_REALTIME: {
        SCOPED_LOCK(spinlock, &now_lock);
        now = *tp;
        break;
    }
    default:
        return -EINVAL;
    }
    return 0;
}

int time_get_resolution(clockid_t clock_id, struct timespec* res) {
    switch (clock_id) {
    case CLOCK_REALTIME:
    case CLOCK_MONOTONIC:
        res->tv_sec = 0;
        res->tv_nsec = NANOS_PER_SEC / CLK_TCK;
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

static _Atomic(int) minuteswest;
static _Atomic(int) dsttime;

void time_get_timezone(struct timezone* out_tz) {
    if (!out_tz)
        return;
    out_tz->tz_minuteswest = minuteswest;
    out_tz->tz_dsttime = dsttime;
}

int time_set_timezone(const struct timezone* tz) {
    // Linux requires tz_minuteswest to be in (-15hr, +15hr)
    if (tz->tz_minuteswest < -15 * 60 || 15 * 60 < tz->tz_minuteswest)
        return -EINVAL;
    minuteswest = tz->tz_minuteswest;
    dsttime = tz->tz_dsttime;
    return 0;
}
