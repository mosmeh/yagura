#include "syscall.h"
#include <kernel/api/err.h>
#include <kernel/api/errno.h>
#include <kernel/api/sys/time.h>
#include <kernel/api/time.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/sched.h>
#include <kernel/time.h>

time32_t sys_time32(time32_t* user_tloc) {
    struct timespec now;
    int rc = time_now(CLOCK_REALTIME, &now);
    if (IS_ERR(rc))
        return rc;
    time32_t sec = now.tv_sec;
    if (user_tloc) {
        if (copy_to_user(user_tloc, &sec, sizeof(time32_t)))
            return -EFAULT;
    }
    return sec;
}

int sys_stime32(const time32_t* user_t) {
    time32_t t;
    if (copy_from_user(&t, user_t, sizeof(time32_t)))
        return -EFAULT;
    struct timespec tp = {.tv_sec = t};
    return time_set(CLOCK_REALTIME, &tp);
}

int sys_gettimeofday(struct linux_timeval* user_tv, struct timezone* user_tz) {
    (void)user_tz;
    struct timespec now;
    int rc = time_now(CLOCK_REALTIME, &now);
    if (IS_ERR(rc))
        return rc;
    struct linux_timeval tv = {
        .tv_sec = now.tv_sec,
        .tv_usec = divmodi64(now.tv_nsec, 1000, NULL),
    };
    if (copy_to_user(user_tv, &tv, sizeof(struct linux_timeval)))
        return -EFAULT;
    return 0;
}

int sys_settimeofday(const struct linux_timeval* user_tv,
                     const struct timezone* user_tz) {
    (void)user_tz;
    struct linux_timeval tv;
    if (copy_from_user(&tv, user_tv, sizeof(struct linux_timeval)))
        return -EFAULT;
    struct timespec tp = {
        .tv_sec = tv.tv_sec,
        .tv_nsec = (long long)tv.tv_usec * 1000,
    };
    return time_set(CLOCK_REALTIME, &tp);
}

int sys_clock_gettime(clockid_t clockid, struct timespec* user_tp) {
    struct timespec tp;
    int rc = time_now(clockid, &tp);
    if (IS_ERR(rc))
        return rc;
    if (copy_to_user(user_tp, &tp, sizeof(struct timespec)))
        return -EINVAL;
    return 0;
}

int sys_clock_settime(clockid_t clockid, const struct timespec* user_tp) {
    struct timespec tp;
    if (copy_from_user(&tp, user_tp, sizeof(struct timespec)))
        return -EFAULT;
    return time_set(clockid, &tp);
}

int sys_clock_getres(clockid_t clockid, struct timespec* user_res) {
    struct timespec res;
    int rc = time_get_resolution(clockid, &res);
    if (IS_ERR(rc))
        return rc;
    if (copy_to_user(user_res, &res, sizeof(struct timespec)))
        return -EINVAL;
    return 0;
}

int sys_clock_gettime32(clockid_t clockid, struct timespec32* user_tp) {
    struct timespec tp;
    int rc = time_now(clockid, &tp);
    if (IS_ERR(rc))
        return rc;
    struct timespec32 tp32 = {
        .tv_sec = tp.tv_sec,
        .tv_nsec = tp.tv_nsec,
    };
    if (copy_to_user(user_tp, &tp32, sizeof(struct timespec32)))
        return -EINVAL;
    return 0;
}

int sys_clock_settime32(clockid_t clockid, const struct timespec32* user_tp) {
    struct timespec32 tp32;
    if (copy_from_user(&tp32, user_tp, sizeof(struct timespec32)))
        return -EFAULT;
    struct timespec tp = {
        .tv_sec = tp32.tv_sec,
        .tv_nsec = tp32.tv_nsec,
    };
    return time_set(clockid, &tp);
}

int sys_clock_getres_time32(clockid_t clockid, struct timespec32* user_res) {
    struct timespec res;
    int rc = time_get_resolution(clockid, &res);
    if (IS_ERR(rc))
        return rc;
    struct timespec32 res32 = {
        .tv_sec = res.tv_sec,
        .tv_nsec = res.tv_nsec,
    };
    if (copy_to_user(user_res, &res32, sizeof(struct timespec32)))
        return -EINVAL;
    return 0;
}

struct sleep_blocker {
    clockid_t clock_id;
    struct timespec deadline;
};

static bool unblock_sleep(void* data) {
    const struct sleep_blocker* blocker = data;
    struct timespec now;
    ASSERT_OK(time_now(blocker->clock_id, &now));
    return timespec_compare(&now, &blocker->deadline) >= 0;
}

static int clock_nanosleep(clockid_t clockid, int flags,
                           const struct timespec* request,
                           struct timespec* remain) {
    struct timespec deadline = {0};
    // Call time_now regardless of the flags to validate the clockid
    int rc = time_now(clockid, &deadline);
    if (IS_ERR(rc))
        return rc;

    switch (flags) {
    case 0:
        timespec_add(&deadline, request);
        break;
    case TIMER_ABSTIME:
        deadline = *request;
        break;
    default:
        return -EINVAL;
    }

    struct sleep_blocker blocker = {
        .clock_id = clockid,
        .deadline = deadline,
    };
    rc = sched_block(unblock_sleep, &blocker, 0);
    if (IS_ERR(rc))
        return rc;
    if (remain && flags != TIMER_ABSTIME) {
        *remain = deadline;
        struct timespec now;
        rc = time_now(clockid, &now);
        if (IS_ERR(rc))
            return rc;
        timespec_saturating_sub(remain, &now);
    }
    return 0;
}

int sys_clock_nanosleep(clockid_t clockid, int flags,
                        const struct timespec* user_request,
                        struct timespec* user_remain) {
    struct timespec request;
    if (copy_from_user(&request, user_request, sizeof(struct timespec)))
        return -EFAULT;
    struct timespec remain = {0};
    int rc =
        clock_nanosleep(clockid, flags, &request, user_remain ? &remain : NULL);
    if (IS_ERR(rc))
        return rc;
    if (user_remain) {
        if (copy_to_user(user_remain, &remain, sizeof(struct timespec)))
            return -EFAULT;
    }
    return 0;
}

int sys_clock_nanosleep_time32(clockid_t clockid, int flags,
                               const struct timespec32* user_request,
                               struct timespec32* user_remain) {
    struct timespec32 request32;
    if (copy_from_user(&request32, user_request, sizeof(struct timespec32)))
        return -EFAULT;
    struct timespec request = {
        .tv_sec = request32.tv_sec,
        .tv_nsec = request32.tv_nsec,
    };
    struct timespec remain = {0};
    int rc =
        clock_nanosleep(clockid, flags, &request, user_remain ? &remain : NULL);
    if (IS_ERR(rc))
        return rc;
    if (user_remain) {
        struct timespec32 rem = {
            .tv_sec = remain.tv_sec,
            .tv_nsec = remain.tv_nsec,
        };
        if (copy_to_user(user_remain, &rem, sizeof(struct timespec32)))
            return -EFAULT;
    }
    return 0;
}

int sys_nanosleep_time32(const struct timespec32* user_duration,
                         struct timespec32* user_rem) {
    return sys_clock_nanosleep_time32(CLOCK_MONOTONIC, 0, user_duration,
                                      user_rem);
}
