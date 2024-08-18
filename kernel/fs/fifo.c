#include "fs.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/signum.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/poll.h>
#include <kernel/containers/ring_buf.h>
#include <kernel/panic.h>
#include <kernel/task.h>

struct fifo {
    struct inode inode;
    struct ring_buf buf;
    struct mutex lock;
    atomic_size_t num_readers;
    atomic_size_t num_writers;
};

static void fifo_destroy_inode(struct inode* inode) {
    struct fifo* fifo = (struct fifo*)inode;
    ring_buf_destroy(&fifo->buf);
    kfree(fifo);
}

static bool unblock_open(struct file* file) {
    const struct fifo* fifo = (const struct fifo*)file->inode;
    switch (file->flags & O_ACCMODE) {
    case O_RDONLY:
        return fifo->num_writers > 0;
    case O_WRONLY:
        return fifo->num_readers > 0;
    default:
        UNREACHABLE();
    }
}

static int fifo_open(struct file* file, mode_t mode) {
    (void)mode;

    struct fifo* fifo = (struct fifo*)file->inode;
    switch (file->flags & O_ACCMODE) {
    case O_RDONLY:
        ++fifo->num_readers;
        break;
    case O_WRONLY:
        ++fifo->num_writers;
        break;
    default:
        return -EINVAL;
    }

    if (file->inode->dev == 0) {
        // This is a fifo created by pipe syscall.
        // We don't need to block here.
        return 0;
    }

    int rc = file_block(file, unblock_open, 0);
    if (rc == -EAGAIN && (file->flags & O_ACCMODE) == O_WRONLY)
        return -ENXIO;
    return rc;
}

static int fifo_close(struct file* file) {
    struct fifo* fifo = (struct fifo*)file->inode;
    switch (file->flags & O_ACCMODE) {
    case O_RDONLY:
        --fifo->num_readers;
        break;
    case O_WRONLY:
        --fifo->num_writers;
        break;
    default:
        UNREACHABLE();
    }
    return 0;
}

static bool unblock_read(struct file* file) {
    const struct fifo* fifo = (const struct fifo*)file->inode;
    return fifo->num_writers == 0 || !ring_buf_is_empty(&fifo->buf);
}

static ssize_t fifo_read(struct file* file, void* buffer, size_t count) {
    struct fifo* fifo = (struct fifo*)file->inode;
    struct ring_buf* buf = &fifo->buf;

    for (;;) {
        int rc = file_block(file, unblock_read, 0);
        if (IS_ERR(rc))
            return rc;

        mutex_lock(&fifo->lock);
        if (!ring_buf_is_empty(buf)) {
            ssize_t nread = ring_buf_read(buf, buffer, count);
            mutex_unlock(&fifo->lock);
            return nread;
        }

        bool no_writer = fifo->num_writers == 0;
        mutex_unlock(&fifo->lock);
        if (no_writer)
            return 0;
    }
}

static bool unblock_write(struct file* file) {
    const struct fifo* fifo = (const struct fifo*)file->inode;
    return fifo->num_readers == 0 || !ring_buf_is_full(&fifo->buf);
}

static ssize_t fifo_write(struct file* file, const void* buffer, size_t count) {
    struct fifo* fifo = (struct fifo*)file->inode;
    struct ring_buf* buf = &fifo->buf;

    for (;;) {
        int rc = file_block(file, unblock_write, 0);
        if (IS_ERR(rc))
            return rc;

        mutex_lock(&fifo->lock);
        if (fifo->num_readers == 0) {
            mutex_unlock(&fifo->lock);
            int rc = task_send_signal(current->tgid, SIGPIPE,
                                      SIGNAL_DEST_THREAD_GROUP);
            if (IS_ERR(rc))
                return rc;
            return -EPIPE;
        }

        if (ring_buf_is_full(buf)) {
            mutex_unlock(&fifo->lock);
            continue;
        }

        ssize_t nwritten = ring_buf_write(buf, buffer, count);
        mutex_unlock(&fifo->lock);
        return nwritten;
    }
}

static short fifo_poll(struct file* file, short events) {
    short revents = 0;
    const struct fifo* fifo = (const struct fifo*)file->inode;
    if ((events & POLLIN) && !ring_buf_is_empty(&fifo->buf))
        revents |= POLLIN;
    if ((events & POLLOUT) && !ring_buf_is_full(&fifo->buf))
        revents |= POLLOUT;
    switch (file->flags & O_ACCMODE) {
    case O_RDONLY:
        if (fifo->num_writers == 0)
            revents |= POLLHUP;
        break;
    case O_WRONLY:
        if (fifo->num_readers == 0)
            revents |= POLLERR;
        break;
    default:
        UNREACHABLE();
    }
    return revents;
}

struct inode* fifo_create(void) {
    struct fifo* fifo = kmalloc(sizeof(struct fifo));
    if (!fifo)
        return ERR_PTR(-ENOMEM);
    *fifo = (struct fifo){0};

    int rc = ring_buf_init(&fifo->buf, PIPE_BUF);
    if (IS_ERR(rc)) {
        kfree(fifo);
        return ERR_PTR(rc);
    }

    struct inode* inode = &fifo->inode;
    static const struct file_ops fops = {
        .destroy_inode = fifo_destroy_inode,
        .open = fifo_open,
        .close = fifo_close,
        .read = fifo_read,
        .write = fifo_write,
        .poll = fifo_poll,
    };
    inode->fops = &fops;
    inode->mode = S_IFIFO;
    inode->ref_count = 1;

    return (struct inode*)fifo;
}
