#include "api/time.h"
#include "drivers/pit.h"
#include "drivers/rtc.h"
#include "interrupts.h"
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

atomic_uint uptime;
static struct timespec now;

static void tick(void) {
    ++uptime;

    bool int_flag = push_cli();
    now.tv_nsec += NANOS / CLK_TCK;
    if (now.tv_nsec >= NANOS) {
        ++now.tv_sec;
        now.tv_nsec -= NANOS;
    }
    pop_cli(int_flag);
}

void time_init(void) {
    now.tv_sec = rtc_now();
    now.tv_nsec = 0;
    pit_set_tick_handler(tick);
}

void time_now(struct timespec* tp) {
    bool int_flag = push_cli();
    *tp = now;
    pop_cli(int_flag);
}
