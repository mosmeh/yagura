#include "api/time.h"
#include "api/errno.h"
#include "drivers/rtc.h"
#include "lock.h"
#include "time.h"

#define NANOS 1000000000

void timespec_add(struct timespec* this, const struct timespec* other) {
    this->tv_sec += other->tv_sec;
    this->tv_nsec += other->tv_nsec;
    if (this->tv_nsec >= NANOS) {
        ++this->tv_sec;
        this->tv_nsec -= NANOS;
    }
}

void timespec_saturating_sub(struct timespec* this,
                             const struct timespec* other) {
    this->tv_sec -= other->tv_sec;
    this->tv_nsec -= other->tv_nsec;
    if (this->tv_nsec < 0) {
        --this->tv_sec;
        this->tv_nsec += NANOS;
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

volatile atomic_uint uptime;
static struct timespec now;
static struct spinlock now_lock;

void time_init(void) { now.tv_sec = rtc_now(); }

void time_tick(void) {
    ++uptime;

    spinlock_lock(&now_lock);
    now.tv_nsec += NANOS / CLK_TCK;
    if (now.tv_nsec >= NANOS) {
        ++now.tv_sec;
        now.tv_nsec -= NANOS;
    }
    spinlock_unlock(&now_lock);
}

int time_now(clockid_t clock_id, struct timespec* tp) {
    switch (clock_id) {
    case CLOCK_REALTIME:
        spinlock_lock(&now_lock);
        *tp = now;
        spinlock_unlock(&now_lock);
        break;
    case CLOCK_MONOTONIC: {
        unsigned t = uptime;
        tp->tv_sec = t / CLK_TCK;
        tp->tv_nsec = (t - tp->tv_sec * CLK_TCK) * NANOS / CLK_TCK;
        break;
    }
    default:
        return -EINVAL;
    }
    return 0;
}
