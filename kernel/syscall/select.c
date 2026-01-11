#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/time.h>
#include <kernel/fs/file.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

struct fd_waiter {
    nfds_t nfds;
    struct pollfd* pollfds;
    struct file** files;
    bool has_timeout;
    struct timespec deadline;
    size_t num_events;
};

static bool unblock_wait_fds(void* data) {
    struct fd_waiter* waiter = data;
    for (nfds_t i = 0; i < waiter->nfds; ++i) {
        struct file* file = waiter->files[i];
        if (!file)
            continue;

        struct pollfd* pollfd = waiter->pollfds + i;
        pollfd->revents = file_poll(file, pollfd->events);
        ASSERT_OK(pollfd->revents);
        ASSERT((pollfd->revents & ~pollfd->events) == 0);
        if (pollfd->revents)
            ++waiter->num_events;
    }
    if (waiter->num_events > 0)
        return true;

    // Check timeout AFTER polling files to update revents even when
    // it immediately times out.
    if (waiter->has_timeout) {
        struct timespec now;
        ASSERT_OK(time_now(CLOCK_MONOTONIC, &now));
        if (timespec_compare(&now, &waiter->deadline) >= 0)
            return true;
    }

    return false;
}

// The differences from poll(2) are:
// - The timeout is struct timespec.
//   On success, updates the timeout to reflect the remaining time.
// - Does not poll for POLLERR or POLLHUP unless requested.
NODISCARD static int wait_fds(nfds_t nfds, struct pollfd pollfds[nfds],
                              struct timespec* timeout) {
    if (timeout) {
        if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
            timeout->tv_nsec >= NANOS_PER_SEC)
            return -EINVAL;
    }

    int ret = 0;
    struct fd_waiter waiter = {
        .nfds = nfds,
        .pollfds = pollfds,
    };

    if (nfds > 0) {
        waiter.files = kmalloc(sizeof(struct file*) * nfds);
        if (!waiter.files) {
            ret = -ENOMEM;
            goto fail;
        }

        struct files* files = current->files;
        for (nfds_t i = 0; i < nfds; ++i) {
            struct pollfd* pollfd = pollfds + i;
            pollfd->revents = 0;
            waiter.files[i] = NULL;
            if (pollfd->fd < 0)
                continue;
            struct file* file = files_ref_file(files, pollfd->fd);
            if (IS_ERR(ASSERT(file))) {
                pollfd->revents = POLLNVAL;
                ++waiter.num_events;
                continue;
            }
            waiter.files[i] = file;
        }
    }

    if (timeout) {
        struct timespec deadline;
        ret = time_now(CLOCK_MONOTONIC, &deadline);
        if (IS_ERR(ret))
            goto fail;
        timespec_add(&deadline, timeout);
        waiter.has_timeout = true;
        waiter.deadline = deadline;
    }

    ret = sched_block(unblock_wait_fds, &waiter, 0);
    if (IS_ERR(ret))
        goto fail;

    if (timeout) {
        *timeout = waiter.deadline;
        struct timespec now;
        ret = time_now(CLOCK_MONOTONIC, &now);
        if (IS_ERR(ret))
            goto fail;
        timespec_saturating_sub(timeout, &now);
    }

    ret = waiter.num_events;

fail:
    if (waiter.files) {
        for (nfds_t i = 0; i < nfds; ++i)
            file_unref(waiter.files[i]);
        kfree(waiter.files);
    }
    return ret;
}

NODISCARD static int
copy_timespec_from_user32(struct timespec* ts,
                          const struct timespec32* user_ts32) {
    struct timespec32 ts32;
    if (copy_from_user(&ts32, user_ts32, sizeof(struct timespec32)))
        return -EFAULT;
    ts->tv_sec = ts32.tv_sec;
    ts->tv_nsec = ts32.tv_nsec;
    return 0;
}

NODISCARD static int copy_timespec_to_user32(struct timespec32* user_ts32,
                                             const struct timespec* ts) {
    struct timespec32 ts32 = {
        .tv_sec = ts->tv_sec,
        .tv_nsec = ts->tv_nsec,
    };
    if (copy_to_user(user_ts32, &ts32, sizeof(struct timespec32)))
        return -EFAULT;
    return 0;
}

NODISCARD static int poll(struct pollfd* user_fds, nfds_t nfds,
                          struct timespec* timeout) {
    size_t pollfds_size = sizeof(struct pollfd) * nfds;
    struct pollfd* pollfds FREE(kfree) = NULL;
    if (nfds > 0) {
        pollfds = kmalloc(pollfds_size);
        if (!pollfds)
            return -ENOMEM;
        if (copy_from_user(pollfds, user_fds, pollfds_size))
            return -EFAULT;
        for (nfds_t i = 0; i < nfds; ++i)
            pollfds[i].events |= POLLERR | POLLHUP;
    }

    int ret = wait_fds(nfds, pollfds, timeout);
    if (IS_ERR(ret))
        return ret;

    if (nfds > 0) {
        if (copy_to_user(user_fds, pollfds, pollfds_size))
            return -EFAULT;
    }

    return ret;
}

long sys_poll(struct pollfd* user_fds, nfds_t nfds, int timeout) {
    struct timespec ts_timeout;
    bool has_timeout = false;
    if (timeout >= 0) { // Negative timeout means infinite.
        ts_timeout = (struct timespec){
            .tv_sec = timeout / MILLIS_PER_SEC,
            .tv_nsec = (timeout % MILLIS_PER_SEC) * 1000000LL,
        };
        has_timeout = true;
    }
    return poll(user_fds, nfds, has_timeout ? &ts_timeout : NULL);
}

long sys_ppoll(struct pollfd* user_fds, nfds_t nfds,
               struct timespec* user_timeout, const sigset_t* user_sigmask,
               size_t sigsetsize) {
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;

    struct timespec timeout;
    if (user_timeout) {
        if (copy_from_user(&timeout, user_timeout, sizeof(struct timespec)))
            return -EFAULT;
    }

    sigset_t old_sigmask = 0;
    if (user_sigmask) {
        sigset_t sigmask;
        if (copy_from_user(&sigmask, user_sigmask, sizeof(sigset_t)))
            return -EFAULT;
        old_sigmask = task_set_blocked_signals(current, sigmask);
    }

    int ret = poll(user_fds, nfds, user_timeout ? &timeout : NULL);

    if (user_sigmask)
        task_set_blocked_signals(current, old_sigmask);

    if (user_timeout) {
        if (copy_to_user(user_timeout, &timeout, sizeof(struct timespec)))
            return -EFAULT;
    }

    return ret;
}

long sys_ppoll_time32(struct pollfd* user_fds, nfds_t nfds,
                      struct timespec32* user_timeout,
                      const sigset_t* user_sigmask, size_t sigsetsize) {
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;

    struct timespec timeout;
    if (user_timeout) {
        if (copy_timespec_from_user32(&timeout, user_timeout))
            return -EFAULT;
    }

    sigset_t old_sigmask = 0;
    if (user_sigmask) {
        sigset_t sigmask;
        if (copy_from_user(&sigmask, user_sigmask, sizeof(sigset_t)))
            return -EFAULT;
        old_sigmask = task_set_blocked_signals(current, sigmask);
    }

    int ret = poll(user_fds, nfds, user_timeout ? &timeout : NULL);

    if (user_sigmask)
        task_set_blocked_signals(current, old_sigmask);

    if (user_timeout) {
        if (copy_timespec_to_user32(user_timeout, &timeout))
            return -EFAULT;
    }

    return ret;
}

#define NUM_FD_BITS (8 * sizeof(unsigned long))

#define FD_CLR(fd, set)                                                        \
    ((set)[(fd) / NUM_FD_BITS] &= ~(1UL << ((fd) % NUM_FD_BITS)))

#define FD_ISSET(fd, set)                                                      \
    ((set)[(fd) / NUM_FD_BITS] & (1UL << ((fd) % NUM_FD_BITS)))

#define READ_SET (POLLIN | POLLERR | POLLHUP | POLLNVAL)
#define WRITE_SET (POLLOUT | POLLERR | POLLNVAL)
#define EXCEPT_SET (POLLPRI | POLLNVAL)

NODISCARD static int select(int nfds, unsigned long* user_readfds,
                            unsigned long* user_writefds,
                            unsigned long* user_exceptfds,
                            struct timespec* timeout) {
    if (nfds < 0)
        return -EINVAL;

    size_t num_fd_bytes = 0;
    unsigned long* fds FREE(kfree) = NULL;
    unsigned long* readfds = NULL;
    unsigned long* writefds = NULL;
    unsigned long* exceptfds = NULL;
    size_t num_pollfds = 0;
    struct pollfd* pollfds FREE(kfree) = NULL;

    if (nfds > 0) {
        size_t num_fd_longs = DIV_CEIL(nfds, NUM_FD_BITS);
        num_fd_bytes = sizeof(unsigned long) * num_fd_longs;

        fds = kmalloc(num_fd_bytes * 3);
        if (!fds)
            return -ENOMEM;
        memset(fds, 0, num_fd_bytes * 3);

        readfds = fds;
        writefds = fds + num_fd_longs;
        exceptfds = fds + num_fd_longs * 2;

        if (user_readfds) {
            if (copy_from_user(readfds, user_readfds, num_fd_bytes))
                return -EFAULT;
        }
        if (user_writefds) {
            if (copy_from_user(writefds, user_writefds, num_fd_bytes))
                return -EFAULT;
        }
        if (user_exceptfds) {
            if (copy_from_user(exceptfds, user_exceptfds, num_fd_bytes))
                return -EFAULT;
        }

        for (int i = 0; i < nfds; ++i) {
            if (FD_ISSET(i, readfds) || FD_ISSET(i, writefds) ||
                FD_ISSET(i, exceptfds))
                ++num_pollfds;
        }

        pollfds = kmalloc(sizeof(struct pollfd) * num_pollfds);
        if (!pollfds)
            return -ENOMEM;

        struct pollfd* pollfd = pollfds;
        for (int i = 0; i < nfds; ++i) {
            if (!FD_ISSET(i, readfds) && !FD_ISSET(i, writefds) &&
                !FD_ISSET(i, exceptfds))
                continue;

            *pollfd = (struct pollfd){.fd = i};
            if (FD_ISSET(i, readfds))
                pollfd->events |= READ_SET;
            if (FD_ISSET(i, writefds))
                pollfd->events |= WRITE_SET;
            if (FD_ISSET(i, exceptfds))
                pollfd->events |= EXCEPT_SET;
            ++pollfd;
        }
    }

    int ret = wait_fds(num_pollfds, pollfds, timeout);
    for (size_t i = 0; i < num_pollfds; ++i) {
        if (pollfds[i].revents & POLLNVAL)
            return -EBADF;
    }
    if (IS_ERR(ret))
        return ret;

    if (nfds > 0) {
        for (size_t i = 0; i < num_pollfds; ++i) {
            struct pollfd* pollfd = pollfds + i;
            if (!(pollfd->revents & READ_SET))
                FD_CLR(pollfd->fd, readfds);
            if (!(pollfd->revents & WRITE_SET))
                FD_CLR(pollfd->fd, writefds);
            if (!(pollfd->revents & EXCEPT_SET))
                FD_CLR(pollfd->fd, exceptfds);
        }

        if (user_readfds) {
            if (copy_to_user(user_readfds, readfds, num_fd_bytes))
                return -EFAULT;
        }
        if (user_writefds) {
            if (copy_to_user(user_writefds, writefds, num_fd_bytes))
                return -EFAULT;
        }
        if (user_exceptfds) {
            if (copy_to_user(user_exceptfds, exceptfds, num_fd_bytes))
                return -EFAULT;
        }
    }

    size_t num_ready = 0;
    for (int i = 0; i < nfds; ++i) {
        if (FD_ISSET(i, readfds))
            ++num_ready;
        if (FD_ISSET(i, writefds))
            ++num_ready;
        if (FD_ISSET(i, exceptfds))
            ++num_ready;
    }
    return num_ready;
}

long sys_select(int nfds, unsigned long* user_readfds,
                unsigned long* user_writefds, unsigned long* user_exceptfds,
                struct linux_timeval* user_timeout) {
    struct timespec ts_timeout;
    if (user_timeout) {
        struct linux_timeval tv_timeout;
        if (copy_from_user(&tv_timeout, user_timeout, sizeof(tv_timeout)))
            return -EFAULT;
        ts_timeout = (struct timespec){
            .tv_sec = tv_timeout.tv_sec + tv_timeout.tv_usec / MICROS_PER_SEC,
            .tv_nsec = (tv_timeout.tv_usec % MICROS_PER_SEC) * 1000LL,
        };
    }

    int ret = select(nfds, user_readfds, user_writefds, user_exceptfds,
                     user_timeout ? &ts_timeout : NULL);

    if (user_timeout) {
        struct linux_timeval tv_timeout = {
            .tv_sec = ts_timeout.tv_sec,
            .tv_usec = ts_timeout.tv_nsec / 1000,
        };
        if (copy_to_user(user_timeout, &tv_timeout, sizeof(tv_timeout)))
            return -EFAULT;
    }

    return ret;
}

long sys_pselect6(int nfds, unsigned long* user_readfds,
                  unsigned long* user_writefds, unsigned long* user_exceptfds,
                  struct timespec* user_timeout, const sigset_t* user_sigmask) {
    struct timespec timeout;
    if (user_timeout) {
        if (copy_from_user(&timeout, user_timeout, sizeof(struct timespec)))
            return -EFAULT;
    }

    sigset_t old_sigmask = 0;
    if (user_sigmask) {
        sigset_t sigmask;
        if (copy_from_user(&sigmask, user_sigmask, sizeof(sigset_t)))
            return -EFAULT;
        old_sigmask = task_set_blocked_signals(current, sigmask);
    }

    int ret = select(nfds, user_readfds, user_writefds, user_exceptfds,
                     user_timeout ? &timeout : NULL);

    if (user_sigmask)
        task_set_blocked_signals(current, old_sigmask);

    if (user_timeout) {
        if (copy_to_user(user_timeout, &timeout, sizeof(struct timespec)))
            return -EFAULT;
    }

    return ret;
}

long sys_pselect6_time32(int nfds, unsigned long* user_readfds,
                         unsigned long* user_writefds,
                         unsigned long* user_exceptfds,
                         struct timespec32* user_timeout,
                         const sigset_t* user_sigmask) {
    struct timespec timeout;
    if (user_timeout) {
        if (copy_timespec_from_user32(&timeout, user_timeout))
            return -EFAULT;
    }

    sigset_t old_sigmask = 0;
    if (user_sigmask) {
        sigset_t sigmask;
        if (copy_from_user(&sigmask, user_sigmask, sizeof(sigset_t)))
            return -EFAULT;
        old_sigmask = task_set_blocked_signals(current, sigmask);
    }

    int ret = select(nfds, user_readfds, user_writefds, user_exceptfds,
                     user_timeout ? &timeout : NULL);

    if (user_sigmask)
        task_set_blocked_signals(current, old_sigmask);

    if (user_timeout) {
        if (copy_timespec_to_user32(user_timeout, &timeout))
            return -EFAULT;
    }

    return ret;
}

struct sel_arg_struct {
    unsigned long n;
    unsigned long *inp, *outp, *exp;
    struct linux_timeval* tvp;
};

long sys_old_select(struct sel_arg_struct* user_arg) {
    struct sel_arg_struct arg;
    if (copy_from_user(&arg, user_arg, sizeof(arg)))
        return -EFAULT;
    return sys_select(arg.n, arg.inp, arg.outp, arg.exp, arg.tvp);
}
