#pragma once

#include <common/macros.h>
#include <common/tree.h>
#include <kernel/api/time.h>
#include <kernel/task/sched.h>

#define CLK_TCK 250

#define MILLIS_PER_SEC 1000LL
#define MICROS_PER_SEC 1000000LL
#define NANOS_PER_SEC 1000000000LL

struct timespec;
struct timezone;

extern _Atomic(unsigned long) uptime;

void timespec_add(struct timespec*, const struct timespec*);
void timespec_saturating_sub(struct timespec*, const struct timespec*);
int timespec_compare(const struct timespec*, const struct timespec*);

static inline bool timespec_is_valid(const struct timespec* ts) {
    return ts->tv_sec >= 0 && 0 <= ts->tv_nsec && ts->tv_nsec < NANOS_PER_SEC;
}

void time_init(void);

void time_tick(void);

NODISCARD int time_now(clockid_t, struct timespec*);
NODISCARD int time_set(clockid_t, const struct timespec*);

NODISCARD int time_get_resolution(clockid_t, struct timespec*);

void time_get_timezone(struct timezone*);
NODISCARD int time_set_timezone(const struct timezone*);

struct timer {
    struct clock* clock;
    struct timespec deadline;
    void (*callback)(struct timer*);
    struct waitqueue wait;
    struct tree_node tree_node;
    _Atomic(enum {
        TIMER_DISARMED,
        TIMER_ARMED,
        TIMER_EXPIRED,
    }) state;
    struct spinlock lock;
};

NODISCARD int timer_init(struct timer*, clockid_t,
                         void (*callback)(struct timer*));

// Arms the timer to expire at the given deadline.
void timer_arm_at(struct timer*, const struct timespec* deadline);

// Arms the timer to expire after the given delay.
void timer_arm_after(struct timer*, const struct timespec* delay);

// Disarms the timer.
void timer_disarm(struct timer*);

// Waits until the timer expires or is disarmed.
// Returns true if the timer expired, false if it was disarmed before expiring.
// If the timer already expired when this function is called, immediately
// returns true.
NODISCARD bool timer_wait(struct timer*);

// Waits until the timer expires, is disarmed, or the task is interrupted by a
// signal.
// Returns 1 if the timer expired, 0 if it was disarmed before expiring,
// or -EINTR if the task was interrupted.
NODISCARD int timer_wait_interruptible(struct timer*);
