#include "fs.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/signal.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/poll.h>
#include <kernel/containers/ring_buf.h>
#include <kernel/panic.h>
#include <kernel/task.h>

struct fifo {
    struct inode inode;
    struct ring_buf buf;
    atomic_size_t num_readers;
    atomic_size_t num_writers;
};

static struct fifo* fifo_from_inode(struct inode* inode) {
    return CONTAINER_OF(inode, struct fifo, inode);
}

static struct fifo* fifo_from_file(struct file* file) {
    return fifo_from_inode(file->inode);
}

static void fifo_destroy(struct inode* inode) {
    struct fifo* fifo = fifo_from_inode(inode);
    ring_buf_destroy(&fifo->buf);
    kfree(fifo);
}

static bool unblock_open(struct file* file) {
    const struct fifo* fifo = fifo_from_file(file);
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

    struct fifo* fifo = fifo_from_file(file);
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
    struct fifo* fifo = fifo_from_file(file);
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
    const struct fifo* fifo = fifo_from_file(file);
    return fifo->num_writers == 0 || !ring_buf_is_empty(&fifo->buf);
}

static ssize_t fifo_pread(struct file* file, void* buffer, size_t count,
                          uint64_t offset) {
    (void)offset;

    struct fifo* fifo = fifo_from_file(file);
    struct ring_buf* buf = &fifo->buf;

    for (;;) {
        int rc = file_block(file, unblock_read, 0);
        if (IS_ERR(rc))
            return rc;

        mutex_lock(&file->inode->lock);
        if (!ring_buf_is_empty(buf)) {
            ssize_t nread = ring_buf_read(buf, buffer, count);
            mutex_unlock(&file->inode->lock);
            return nread;
        }

        bool no_writer = fifo->num_writers == 0;
        mutex_unlock(&file->inode->lock);
        if (no_writer)
            return 0;
    }
}

static bool unblock_write(struct file* file) {
    const struct fifo* fifo = fifo_from_file(file);
    return fifo->num_readers == 0 || !ring_buf_is_full(&fifo->buf);
}

static ssize_t fifo_pwrite(struct file* file, const void* buffer, size_t count,
                           uint64_t offset) {
    (void)offset;

    struct fifo* fifo = fifo_from_file(file);
    struct ring_buf* buf = &fifo->buf;

    for (;;) {
        int rc = file_block(file, unblock_write, 0);
        if (IS_ERR(rc))
            return rc;

        mutex_lock(&file->inode->lock);
        if (fifo->num_readers == 0) {
            mutex_unlock(&file->inode->lock);
            int rc = task_send_signal(current->tid, SIGPIPE, 0);
            if (IS_ERR(rc))
                return rc;
            return -EPIPE;
        }

        if (ring_buf_is_full(buf)) {
            mutex_unlock(&file->inode->lock);
            continue;
        }

        ssize_t nwritten = ring_buf_write(buf, buffer, count);
        mutex_unlock(&file->inode->lock);
        return nwritten;
    }
}

static short fifo_poll(struct file* file, short events) {
    short revents = 0;
    const struct fifo* fifo = fifo_from_file(file);
    if ((events & POLLIN) && !ring_buf_is_empty(&fifo->buf))
        revents |= POLLIN;
    if ((events & POLLOUT) && !ring_buf_is_full(&fifo->buf))
        revents |= POLLOUT;
    switch (file->flags & O_ACCMODE) {
    case O_RDONLY:
        if ((events & POLLHUP) && (fifo->num_writers == 0))
            revents |= POLLHUP;
        break;
    case O_WRONLY:
        if ((events & POLLERR) && (fifo->num_readers == 0))
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
    static const struct inode_ops iops = {
        .destroy = fifo_destroy,
    };
    static const struct file_ops fops = {
        .open = fifo_open,
        .close = fifo_close,
        .pread = fifo_pread,
        .pwrite = fifo_pwrite,
        .poll = fifo_poll,
    };
    inode->iops = &iops;
    inode->fops = &fops;
    inode->mode = S_IFIFO;
    inode->ref_count = 1;

    return inode;
}
