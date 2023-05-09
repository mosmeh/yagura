#include "syscall.h"
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/safe_string.h>
#include <kernel/scheduler.h>
#include <kernel/time.h>

struct poll_blocker {
    nfds_t nfds;
    struct pollfd* fds;
    file_description** descs;
    bool has_timeout;
    struct timespec deadline;
    size_t num_events;
};

static bool poll_should_unblock(struct poll_blocker* blocker) {
    if (blocker->has_timeout) {
        struct timespec now;
        time_now(&now);
        if (timespec_compare(&now, &blocker->deadline) >= 0)
            return true;
    }

    for (nfds_t i = 0; i < blocker->nfds; ++i) {
        file_description* desc = blocker->descs[i];
        if (!desc)
            continue;

        file_ops* fops = desc->inode->fops;
        struct pollfd* fd = blocker->fds + i;
        if (fops->poll) {
            fd->revents = fops->poll(desc, fd->events);
            ASSERT(fd->revents >= 0);
            if (!(fd->events & POLLIN))
                ASSERT(!(fd->revents & POLLIN));
            if (!(fd->events & POLLOUT))
                ASSERT(!(fd->revents & POLLOUT));
        } else {
            fd->revents = fd->events & (POLLIN | POLLOUT);
        }
        if (fd->revents)
            ++blocker->num_events;
    }

    return blocker->num_events > 0;
}

int sys_poll(struct pollfd* user_fds, nfds_t nfds, int timeout) {
    if (timeout == 0)
        return 0;

    int ret = 0;
    struct poll_blocker blocker = {.nfds = nfds};

    if (nfds > 0) {
        size_t fds_size = sizeof(struct pollfd) * nfds;
        blocker.fds = kmalloc(fds_size);
        if (!blocker.fds) {
            ret = -ENOMEM;
            goto exit;
        }
        if (!copy_from_user(blocker.fds, user_fds, fds_size)) {
            ret = -EFAULT;
            goto exit;
        }

        blocker.descs = kmalloc(sizeof(file_description*) * nfds);
        if (!blocker.descs) {
            ret = -ENOMEM;
            goto exit;
        }

        for (nfds_t i = 0; i < nfds; ++i) {
            struct pollfd* fd = blocker.fds + i;
            fd->revents = 0;
            blocker.descs[i] = NULL;
            if (fd->fd < 0)
                continue;
            file_description* desc = process_get_file_description(fd->fd);
            if (IS_ERR(desc)) {
                fd->revents = POLLNVAL;
                ++blocker.num_events;
                continue;
            }
            blocker.descs[i] = desc;
        }
    }

    if (timeout > 0) {
        struct timespec deadline;
        time_now(&deadline);
        struct timespec delta = {.tv_sec = timeout / 1000,
                                 .tv_nsec = (timeout % 1000) * 1000000};
        timespec_add(&deadline, &delta);
        blocker.has_timeout = true;
        blocker.deadline = deadline;
    }

    ret = scheduler_block((should_unblock_fn)poll_should_unblock, &blocker);
    if (IS_ERR(ret))
        goto exit;

    if (nfds > 0) {
        if (!copy_to_user(user_fds, blocker.fds,
                          sizeof(struct pollfd) * nfds)) {
            ret = -EFAULT;
            goto exit;
        }
    }

    ret = blocker.num_events;

exit:
    kfree(blocker.descs);
    kfree(blocker.fds);
    return ret;
}
