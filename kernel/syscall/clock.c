#include "syscall.h"
#include <kernel/api/err.h>
#include <kernel/api/errno.h>
#include <kernel/api/time.h>
#include <kernel/safe_string.h>
#include <kernel/scheduler.h>
#include <kernel/time.h>

int sys_clock_gettime(clockid_t clk_id, struct timespec* user_tp) {
    switch (clk_id) {
    case CLOCK_REALTIME:
    case CLOCK_MONOTONIC: {
        struct timespec tp;
        time_now(&tp);
        if (copy_to_user(user_tp, &tp, sizeof(struct timespec)))
            return -EINVAL;
        return 0;
    }
    default:
        return -EINVAL;
    }
}

static bool unblock_sleep(const struct timespec* deadline) {
    struct timespec now;
    time_now(&now);
    return timespec_compare(&now, deadline) >= 0;
}

int sys_clock_nanosleep(clockid_t clockid, int flags,
                        const struct timespec* user_request,
                        struct timespec* user_remain) {
    switch (clockid) {
    case CLOCK_REALTIME:
    case CLOCK_MONOTONIC:
        break;
    default:
        return -EINVAL;
    }

    struct timespec request;
    if (copy_from_user(&request, user_request, sizeof(struct timespec)))
        return -EFAULT;

    struct timespec deadline = {0};
    switch (flags) {
    case 0: {
        time_now(&deadline);
        timespec_add(&deadline, &request);
        break;
    }
    case TIMER_ABSTIME:
        deadline = request;
        break;
    default:
        return -EINVAL;
    }

    int rc = scheduler_block((unblock_fn)unblock_sleep, &deadline, 0);
    if (IS_ERR(rc))
        return rc;
    if (user_remain && flags != TIMER_ABSTIME) {
        struct timespec remain = deadline;
        struct timespec now;
        time_now(&now);
        timespec_saturating_sub(&remain, &now);
        if (copy_to_user(user_remain, &remain, sizeof(struct timespec)))
            return -EFAULT;
    }
    return 0;
}
