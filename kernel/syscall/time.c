#include <kernel/api/err.h>
#include <kernel/api/errno.h>
#include <kernel/api/sys/time.h>
#include <kernel/api/time.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/sched.h>
#include <kernel/time.h>

NODISCARD static int time(time_t* tloc) {
    struct timespec now;
    int rc = time_now(CLOCK_REALTIME, &now);
    if (IS_ERR(rc))
        return rc;
    if (tloc)
        *tloc = now.tv_sec;
    return 0;
}

SYSCALL1(time, linux_old_time_t*, user_tloc) {
    time_t t;
    int rc = time(&t);
    if (IS_ERR(rc))
        return rc;
    linux_old_time_t old_t = t;
    if (user_tloc) {
        if (copy_to_user(user_tloc, &old_t, sizeof(linux_old_time_t)))
            return -EFAULT;
    }
    return old_t;
}

SYSCALL1(time32, time32_t*, user_tloc) {
    time_t t;
    int rc = time(&t);
    if (IS_ERR(rc))
        return rc;
    time32_t t32 = t;
    if (user_tloc) {
        if (copy_to_user(user_tloc, &t32, sizeof(time32_t)))
            return -EFAULT;
    }
    return t32;
}

SYSCALL1(stime32, const time32_t*, user_t) {
    time32_t t;
    if (copy_from_user(&t, user_t, sizeof(time32_t)))
        return -EFAULT;
    struct timespec tp = {.tv_sec = t};
    return time_set(CLOCK_REALTIME, &tp);
}

SYSCALL2(gettimeofday, struct linux_timeval*, user_tv, struct timezone*,
         user_tz) {
    if (user_tv) {
        struct timespec now;
        int rc = time_now(CLOCK_REALTIME, &now);
        if (IS_ERR(rc))
            return rc;
        struct linux_timeval tv = {
            .tv_sec = now.tv_sec,
            .tv_usec = now.tv_nsec / 1000,
        };
        if (copy_to_user(user_tv, &tv, sizeof(struct linux_timeval)))
            return -EFAULT;
    }
    if (user_tz) {
        struct timezone tz;
        time_get_timezone(&tz);
        if (copy_to_user(user_tz, &tz, sizeof(struct timezone)))
            return -EFAULT;
    }
    return 0;
}

SYSCALL2(settimeofday, const struct linux_timeval*, user_tv,
         const struct timezone*, user_tz) {
    struct timespec tp;
    if (user_tv) {
        struct linux_timeval tv;
        if (copy_from_user(&tv, user_tv, sizeof(struct linux_timeval)))
            return -EFAULT;
        if (tv.tv_usec < 0 || MICROS_PER_SEC < tv.tv_usec)
            return -EINVAL;
        tp = (struct timespec){
            .tv_sec = tv.tv_sec,
            .tv_nsec = (long long)tv.tv_usec * 1000,
        };
    }
    if (user_tz) {
        struct timezone tz;
        if (copy_from_user(&tz, user_tz, sizeof(struct timezone)))
            return -EFAULT;
        int rc = time_set_timezone(&tz);
        if (IS_ERR(rc))
            return rc;
    }
    if (user_tv)
        return time_set(CLOCK_REALTIME, &tp);
    return 0;
}

SYSCALL2(clock_gettime, clockid_t, clockid, struct timespec*, user_tp) {
    struct timespec tp;
    int rc = time_now(clockid, &tp);
    if (IS_ERR(rc))
        return rc;
    if (copy_to_user(user_tp, &tp, sizeof(struct timespec)))
        return -EFAULT;
    return 0;
}

SYSCALL2(clock_settime, clockid_t, clockid, const struct timespec*, user_tp) {
    struct timespec tp;
    if (copy_from_user(&tp, user_tp, sizeof(struct timespec)))
        return -EFAULT;
    return time_set(clockid, &tp);
}

SYSCALL2(clock_getres, clockid_t, clockid, struct timespec*, user_res) {
    struct timespec res;
    int rc = time_get_resolution(clockid, &res);
    if (IS_ERR(rc))
        return rc;
    if (!user_res)
        return 0;
    if (copy_to_user(user_res, &res, sizeof(struct timespec)))
        return -EFAULT;
    return 0;
}

SYSCALL2(clock_gettime32, clockid_t, clockid, struct timespec32*, user_tp) {
    struct timespec tp;
    int rc = time_now(clockid, &tp);
    if (IS_ERR(rc))
        return rc;
    struct timespec32 tp32 = {
        .tv_sec = tp.tv_sec,
        .tv_nsec = tp.tv_nsec,
    };
    if (copy_to_user(user_tp, &tp32, sizeof(struct timespec32)))
        return -EFAULT;
    return 0;
}

SYSCALL2(clock_settime32, clockid_t, clockid, const struct timespec32*,
         user_tp) {
    struct timespec32 tp32;
    if (copy_from_user(&tp32, user_tp, sizeof(struct timespec32)))
        return -EFAULT;
    struct timespec tp = {
        .tv_sec = tp32.tv_sec,
        .tv_nsec = tp32.tv_nsec,
    };
    return time_set(clockid, &tp);
}

SYSCALL2(clock_getres_time32, clockid_t, clockid, struct timespec32*,
         user_res) {
    struct timespec res;
    int rc = time_get_resolution(clockid, &res);
    if (IS_ERR(rc))
        return rc;
    if (!user_res)
        return 0;
    struct timespec32 res32 = {
        .tv_sec = res.tv_sec,
        .tv_nsec = res.tv_nsec,
    };
    if (copy_to_user(user_res, &res32, sizeof(struct timespec32)))
        return -EFAULT;
    return 0;
}

NODISCARD static int clock_nanosleep(clockid_t clockid, int flags,
                                     const struct timespec* request,
                                     struct timespec* remain) {
    struct timer timer CLEANUP(timer_disarm);
    int rc = timer_init(&timer, clockid, NULL);
    if (IS_ERR(rc))
        return rc;

    if (!timespec_is_valid(request))
        return -EINVAL;

    switch (flags) {
    case 0:
        timer_arm_after(&timer, request);
        break;
    case TIMER_ABSTIME:
        timer_arm_at(&timer, request);
        break;
    default:
        return -EINVAL;
    }

    rc = timer_wait_interruptible(&timer);
    if (IS_ERR(rc))
        return rc;

    if (remain && flags != TIMER_ABSTIME) {
        *remain = timer.deadline;
        struct timespec now;
        rc = time_now(clockid, &now);
        if (IS_ERR(rc))
            return rc;
        timespec_saturating_sub(remain, &now);
    }
    return 0;
}

NODISCARD static int clock_nanosleep_time64(clockid_t clockid, int flags,
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

SYSCALL4(clock_nanosleep, clockid_t, clockid, int, flags,
         const struct timespec*, user_request, struct timespec*, user_remain) {
    return clock_nanosleep_time64(clockid, flags, user_request, user_remain);
}

SYSCALL2(nanosleep, const struct timespec*, user_duration, struct timespec*,
         user_rem) {
    return clock_nanosleep_time64(CLOCK_MONOTONIC, 0, user_duration, user_rem);
}

NODISCARD
static int clock_nanosleep_time32(clockid_t clockid, int flags,
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

SYSCALL4(clock_nanosleep_time32, clockid_t, clockid, int, flags,
         const struct timespec32*, user_request, struct timespec32*,
         user_remain) {
    return clock_nanosleep_time32(clockid, flags, user_request, user_remain);
}

SYSCALL2(nanosleep_time32, const struct timespec32*, user_duration,
         struct timespec32*, user_rem) {
    return clock_nanosleep_time32(CLOCK_MONOTONIC, 0, user_duration, user_rem);
}
