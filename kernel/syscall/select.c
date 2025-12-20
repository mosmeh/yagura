#include <common/string.h>
#include <kernel/api/sys/time.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task.h>
#include <kernel/time.h>

struct poll_blocker {
    nfds_t nfds;
    struct pollfd* pollfds;
    struct file** files;
    bool has_timeout;
    struct timespec deadline;
    size_t num_events;
};

static bool unblock_poll(void* data) {
    struct poll_blocker* blocker = data;
    for (nfds_t i = 0; i < blocker->nfds; ++i) {
        struct file* file = blocker->files[i];
        if (!file)
            continue;

        struct pollfd* pollfd = blocker->pollfds + i;
        pollfd->revents = file_poll(file, pollfd->events);
        ASSERT_OK(pollfd->revents);
        ASSERT((pollfd->revents & ~pollfd->events) == 0);
        if (pollfd->revents)
            ++blocker->num_events;
    }
    if (blocker->num_events > 0)
        return true;

    // Check timeout AFTER polling files to update revents even when
    // it immediately times out.
    if (blocker->has_timeout) {
        struct timespec now;
        ASSERT_OK(time_now(CLOCK_MONOTONIC, &now));
        if (timespec_compare(&now, &blocker->deadline) >= 0)
            return true;
    }

    return false;
}

// The differences from poll(2) are:
// - The timeout is struct timespec.
//   On success, updates the timeout to reflect the remaining time.
// - Does not poll for POLLERR or POLLHUP unless requested.
NODISCARD static int poll(nfds_t nfds, struct pollfd pollfds[nfds],
                          struct timespec* timeout) {
    int ret = 0;
    struct poll_blocker blocker = {
        .nfds = nfds,
        .pollfds = pollfds,
    };

    if (nfds > 0) {
        blocker.files = kmalloc(sizeof(struct file*) * nfds);
        if (!blocker.files) {
            ret = -ENOMEM;
            goto fail;
        }

        for (nfds_t i = 0; i < nfds; ++i) {
            struct pollfd* pollfd = pollfds + i;
            pollfd->revents = 0;
            blocker.files[i] = NULL;
            if (pollfd->fd < 0)
                continue;
            struct file* file = task_ref_file(pollfd->fd);
            if (IS_ERR(ASSERT(file))) {
                pollfd->revents = POLLNVAL;
                ++blocker.num_events;
                continue;
            }
            blocker.files[i] = file;
        }
    }

    if (timeout) {
        struct timespec deadline;
        ret = time_now(CLOCK_MONOTONIC, &deadline);
        if (IS_ERR(ret))
            goto fail;
        timespec_add(&deadline, timeout);
        blocker.has_timeout = true;
        blocker.deadline = deadline;
    }

    ret = sched_block(unblock_poll, &blocker, 0);
    if (IS_ERR(ret))
        goto fail;

    if (timeout) {
        *timeout = blocker.deadline;
        struct timespec now;
        ret = time_now(CLOCK_MONOTONIC, &now);
        if (IS_ERR(ret))
            goto fail;
        timespec_saturating_sub(timeout, &now);
    }

    ret = blocker.num_events;

fail:
    if (blocker.files) {
        for (nfds_t i = 0; i < nfds; ++i)
            file_unref(blocker.files[i]);
        kfree(blocker.files);
    }
    return ret;
}

int sys_poll(struct pollfd* user_fds, nfds_t nfds, int timeout) {
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

    struct timespec timeout_ts = {
        .tv_sec = timeout / 1000,
        .tv_nsec = (timeout % 1000) * 1000000LL,
    };
    // Negative timeout means infinite.
    int ret = poll(nfds, pollfds, timeout >= 0 ? &timeout_ts : NULL);
    if (IS_ERR(ret))
        return ret;

    if (nfds > 0) {
        if (copy_to_user(user_fds, pollfds, pollfds_size))
            return -EFAULT;
    }

    return ret;
}

#define NUM_FD_BITS (8 * sizeof(unsigned long))

#define FD_CLR(fd, set)                                                        \
    ((set)[(fd) / NUM_FD_BITS] &= ~(1U << ((fd) % NUM_FD_BITS)))

#define FD_ISSET(fd, set)                                                      \
    ((set)[(fd) / NUM_FD_BITS] & (1U << ((fd) % NUM_FD_BITS)))

#define READ_SET (POLLIN | POLLERR | POLLHUP | POLLNVAL)
#define WRITE_SET (POLLOUT | POLLERR | POLLNVAL)
#define EXCEPT_SET (POLLPRI | POLLNVAL)

int sys_select(int nfds, unsigned long* user_readfds,
               unsigned long* user_writefds, unsigned long* user_exceptfds,
               struct linux_timeval* user_timeout) {
    if (nfds < 0)
        return -EINVAL;

    struct linux_timeval timeout = {0};
    if (user_timeout) {
        if (copy_from_user(&timeout, user_timeout, sizeof(timeout)))
            return -EFAULT;
        if (timeout.tv_sec < 0 || timeout.tv_usec < 0)
            return -EINVAL;
    }

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

    struct timespec timeout_ts = {
        .tv_sec = timeout.tv_sec + timeout.tv_usec / 1000000,
        .tv_nsec = (timeout.tv_usec % 1000000) * 1000LL,
    };

    int ret = poll(num_pollfds, pollfds, user_timeout ? &timeout_ts : NULL);

    for (size_t i = 0; i < num_pollfds; ++i) {
        if (pollfds[i].revents & POLLNVAL)
            return -EBADF;
    }

    // On Linux, timeout is modified even on EINTR.
    if (user_timeout && (IS_OK(ret) || ret == -EINTR)) {
        timeout.tv_sec = timeout_ts.tv_sec;
        timeout.tv_usec = divmodi64(timeout_ts.tv_nsec, 1000, NULL);
        if (copy_to_user(user_timeout, &timeout, sizeof(timeout)))
            return -EFAULT;
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

struct sel_arg_struct {
    unsigned long n;
    unsigned long *inp, *outp, *exp;
    struct linux_timeval* tvp;
};

int sys_old_select(struct sel_arg_struct* user_arg) {
    struct sel_arg_struct arg;
    if (copy_from_user(&arg, user_arg, sizeof(arg)))
        return -EFAULT;
    return sys_select(arg.n, arg.inp, arg.outp, arg.exp, arg.tvp);
}
