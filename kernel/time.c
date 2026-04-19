#include <kernel/api/errno.h>
#include <kernel/api/sys/time.h>
#include <kernel/arch/system.h>
#include <kernel/lock/spinlock.h>
#include <kernel/panic.h>
#include <kernel/task/sched.h>
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

_Atomic(unsigned long) uptime;

void time_init(void) {
    struct timespec now;
    arch_time_now(&now);
    ASSERT_OK(time_set(CLOCK_REALTIME, &now));
}

struct clock {
    struct timespec now;
    struct tree timers;
    struct spinlock lock;
};

DEFINE_LOCKED(clock, struct clock, spinlock, lock)

static struct clock realtime;
static struct clock monotonic;

static struct clock* clock_get(clockid_t clock_id) {
    switch (clock_id) {
    case CLOCK_REALTIME:
        return &realtime;
    case CLOCK_MONOTONIC:
        return &monotonic;
    default:
        return NULL;
    }
}

DEFINE_LOCKED(timer, struct timer, spinlock, lock)

static void timer_expire(struct timer* timer) {
    ASSERT(timer_is_locked_by_current(timer));
    ASSERT(timer->state == TIMER_ARMED);
    timer->state = TIMER_EXPIRED;
    if (timer->callback)
        timer->callback(timer);
    waitqueue_wake_all(&timer->wait);
}

static void clock_expire_timers(struct clock* clock) {
    SCOPED_LOCK(clock, clock);
    for (;;) {
        struct tree_node* node = tree_first(&clock->timers);
        if (!node)
            break;
        struct timer* timer = CONTAINER_OF(node, struct timer, tree_node);
        SCOPED_LOCK(timer, timer);
        ASSERT(timer->state == TIMER_ARMED);
        if (timespec_compare(&clock->now, &timer->deadline) < 0)
            break;
        tree_remove(&clock->timers, node);
        timer_expire(timer);
    }
}

static void clock_advance(struct clock* clock, const struct timespec* amount) {
    SCOPED_LOCK(clock, clock);
    timespec_add(&clock->now, amount);
    clock_expire_timers(clock);
}

int timer_init(struct timer* timer, clockid_t clock_id,
               void (*callback)(struct timer*)) {
    struct clock* clock = clock_get(clock_id);
    if (clock) {
        *timer = (struct timer){
            .state = TIMER_DISARMED,
            .clock = clock,
            .callback = callback,
        };
        return 0;
    }
    *timer = (struct timer){
        .state = TIMER_DISARMED,
    };
    return -EINVAL;
}

void timer_arm_at(struct timer* timer, const struct timespec* deadline) {
    struct clock* clock = ASSERT_PTR(timer->clock);
    SCOPED_LOCK(clock, clock);

    SCOPED_LOCK(timer, timer);
    ASSERT(timer->state != TIMER_ARMED);
    timer->state = TIMER_ARMED;
    timer->deadline = *deadline;

    if (timespec_compare(&clock->now, deadline) >= 0) {
        timer_expire(timer);
        return;
    }

    struct tree_node** new_node = &clock->timers.root;
    struct tree_node* parent = NULL;
    while (*new_node) {
        parent = *new_node;
        struct timer* entry = CONTAINER_OF(parent, struct timer, tree_node);
        if (timespec_compare(deadline, &entry->deadline) < 0) {
            new_node = &parent->left;
        } else {
            // New timers with the same deadline are ordered after existing ones
            // to ensure FIFO expiration order.
            new_node = &parent->right;
        }
    }
    *new_node = &timer->tree_node;
    tree_insert(&clock->timers, parent, *new_node);
}

void timer_arm_after(struct timer* timer, const struct timespec* delay) {
    struct clock* clock = ASSERT_PTR(timer->clock);
    SCOPED_LOCK(clock, clock);
    struct timespec deadline = clock->now;
    timespec_add(&deadline, delay);
    timer_arm_at(timer, &deadline);
}

void timer_disarm(struct timer* timer) {
    if (!timer)
        return;
    struct clock* clock = timer->clock;
    if (!clock) {
        // Initialization must have failed
        return;
    }
    SCOPED_LOCK(clock, clock);
    SCOPED_LOCK(timer, timer);
    if (timer->state == TIMER_ARMED)
        tree_remove(&clock->timers, &timer->tree_node);
    timer->state = TIMER_DISARMED;
    timer->deadline = (struct timespec){0};
    waitqueue_wake_all(&timer->wait);
}

bool timer_wait(struct timer* timer) {
    for (;;) {
        WAIT(&timer->wait, timer->state != TIMER_ARMED);
        switch (timer->state) {
        case TIMER_DISARMED:
            return false;
        case TIMER_ARMED:
            break;
        case TIMER_EXPIRED:
            return true;
        default:
            UNREACHABLE();
        }
    }
}

int timer_wait_interruptible(struct timer* timer) {
    for (;;) {
        if (WAIT_INTERRUPTIBLE(&timer->wait, timer->state != TIMER_ARMED))
            return -EINTR;
        switch (timer->state) {
        case TIMER_DISARMED:
            return 0;
        case TIMER_ARMED:
            break;
        case TIMER_EXPIRED:
            return 1;
        default:
            UNREACHABLE();
        }
    }
}

void time_tick(void) {
    ++uptime;

    static const struct timespec increment = {
        .tv_nsec = NANOS_PER_SEC / CLK_TCK,
    };
    clock_advance(&realtime, &increment);
    clock_advance(&monotonic, &increment);
}

int time_now(clockid_t clock_id, struct timespec* out_tp) {
    struct clock* clock = clock_get(clock_id);
    if (!clock)
        return -EINVAL;
    if (out_tp) {
        SCOPED_LOCK(clock, clock);
        *out_tp = clock->now;
    }
    return 0;
}

int time_set(clockid_t clock_id, const struct timespec* tp) {
    if (!timespec_is_valid(tp))
        return -EINVAL;

    switch (clock_id) {
    case CLOCK_REALTIME:
        break;
    default:
        return -EINVAL;
    }

    struct clock* clock = ASSERT_PTR(clock_get(clock_id));
    SCOPED_LOCK(clock, clock);
    clock->now = *tp;
    clock_expire_timers(clock);
    return 0;
}

int time_get_resolution(clockid_t clock_id, struct timespec* res) {
    struct clock* clock = clock_get(clock_id);
    if (!clock)
        return -EINVAL;
    res->tv_sec = 0;
    res->tv_nsec = NANOS_PER_SEC / CLK_TCK;
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
