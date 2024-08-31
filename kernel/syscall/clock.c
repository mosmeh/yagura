#include "syscall.h"
#include <kernel/api/err.h>
#include <kernel/api/errno.h>
#include <kernel/api/time.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/sched.h>
#include <kernel/time.h>

int sys_clock_gettime(clockid_t clk_id, struct timespec* user_tp) {
    struct timespec tp;
    int rc = time_now(clk_id, &tp);
    if (IS_ERR(rc))
        return rc;
    if (copy_to_user(user_tp, &tp, sizeof(struct timespec)))
        return -EINVAL;
    return 0;
}

struct sleep_blocker {
    clockid_t clock_id;
    struct timespec deadline;
};

static bool unblock_sleep(const struct sleep_blocker* blocker) {
    struct timespec now;
    ASSERT_OK(time_now(blocker->clock_id, &now));
    return timespec_compare(&now, &blocker->deadline) >= 0;
}

int sys_clock_nanosleep(clockid_t clockid, int flags,
                        const struct timespec* user_request,
                        struct timespec* user_remain) {
    struct timespec request;
    if (copy_from_user(&request, user_request, sizeof(struct timespec)))
        return -EFAULT;

    struct timespec deadline = {0};
    // Call time_now regardless of the flags to validate the clockid
    int rc = time_now(clockid, &deadline);
    if (IS_ERR(rc))
        return rc;

    switch (flags) {
    case 0:
        timespec_add(&deadline, &request);
        break;
    case TIMER_ABSTIME:
        deadline = request;
        break;
    default:
        return -EINVAL;
    }

    struct sleep_blocker blocker = {.clock_id = clockid, .deadline = deadline};
    rc = sched_block((unblock_fn)unblock_sleep, &blocker, 0);
    if (IS_ERR(rc))
        return rc;
    if (user_remain && flags != TIMER_ABSTIME) {
        struct timespec remain = deadline;
        struct timespec now;
        rc = time_now(clockid, &now);
        if (IS_ERR(rc))
            return rc;
        timespec_saturating_sub(&remain, &now);
        if (copy_to_user(user_remain, &remain, sizeof(struct timespec)))
            return -EFAULT;
    }
    return 0;
}
