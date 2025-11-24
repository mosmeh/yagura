#include "fs.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/signal.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/poll.h>
#include <kernel/containers/ring_buf.h>
#include <kernel/panic.h>
#include <kernel/task.h>

struct pipe {
    struct inode inode;
    struct ring_buf buf;
    atomic_size_t num_readers;
    atomic_size_t num_writers;
};

static struct pipe* pipe_from_inode(struct inode* inode) {
    return CONTAINER_OF(inode, struct pipe, inode);
}

static struct pipe* pipe_from_file(struct file* file) {
    return pipe_from_inode(file->inode);
}

static void pipe_destroy(struct inode* inode) {
    struct pipe* pipe = pipe_from_inode(inode);
    ring_buf_destroy(&pipe->buf);
    kfree(pipe);
}

static bool unblock_open(struct file* file) {
    const struct pipe* pipe = pipe_from_file(file);
    switch (file->flags & O_ACCMODE) {
    case O_RDONLY:
        return pipe->num_writers > 0;
    case O_WRONLY:
        return pipe->num_readers > 0;
    default:
        UNREACHABLE();
    }
}

static int pipe_open(struct file* file) {
    struct pipe* pipe = pipe_from_file(file);
    switch (file->flags & O_ACCMODE) {
    case O_RDONLY:
        ++pipe->num_readers;
        break;
    case O_WRONLY:
        ++pipe->num_writers;
        break;
    default:
        return -EINVAL;
    }

    if (file->inode->dev == 0) {
        // This is a pipe created by pipe syscall.
        // We don't need to block here.
        return 0;
    }

    int rc = file_block(file, unblock_open, 0);
    if (rc == -EAGAIN && (file->flags & O_ACCMODE) == O_WRONLY)
        return -ENXIO;
    return rc;
}

static int pipe_close(struct file* file) {
    struct pipe* pipe = pipe_from_file(file);
    switch (file->flags & O_ACCMODE) {
    case O_RDONLY:
        --pipe->num_readers;
        break;
    case O_WRONLY:
        --pipe->num_writers;
        break;
    default:
        UNREACHABLE();
    }
    return 0;
}

static bool unblock_read(struct file* file) {
    const struct pipe* pipe = pipe_from_file(file);
    return pipe->num_writers == 0 || !ring_buf_is_empty(&pipe->buf);
}

static ssize_t pipe_pread(struct file* file, void* buffer, size_t count,
                          uint64_t offset) {
    (void)offset;

    struct pipe* pipe = pipe_from_file(file);
    struct ring_buf* buf = &pipe->buf;

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

        bool no_writer = pipe->num_writers == 0;
        mutex_unlock(&file->inode->lock);
        if (no_writer)
            return 0;
    }
}

static bool unblock_write(struct file* file) {
    const struct pipe* pipe = pipe_from_file(file);
    return pipe->num_readers == 0 || !ring_buf_is_full(&pipe->buf);
}

static ssize_t pipe_pwrite(struct file* file, const void* buffer, size_t count,
                           uint64_t offset) {
    (void)offset;

    struct pipe* pipe = pipe_from_file(file);
    struct ring_buf* buf = &pipe->buf;

    for (;;) {
        int rc = file_block(file, unblock_write, 0);
        if (IS_ERR(rc))
            return rc;

        mutex_lock(&file->inode->lock);
        if (pipe->num_readers == 0) {
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

static short pipe_poll(struct file* file, short events) {
    short revents = 0;
    const struct pipe* pipe = pipe_from_file(file);
    if ((events & POLLIN) && !ring_buf_is_empty(&pipe->buf))
        revents |= POLLIN;
    if ((events & POLLOUT) && !ring_buf_is_full(&pipe->buf))
        revents |= POLLOUT;
    switch (file->flags & O_ACCMODE) {
    case O_RDONLY:
        if ((events & POLLHUP) && (pipe->num_writers == 0))
            revents |= POLLHUP;
        break;
    case O_WRONLY:
        if ((events & POLLERR) && (pipe->num_readers == 0))
            revents |= POLLERR;
        break;
    default:
        UNREACHABLE();
    }
    return revents;
}

struct inode* pipe_create(void) {
    struct pipe* pipe = kmalloc(sizeof(struct pipe));
    if (!pipe)
        return ERR_PTR(-ENOMEM);
    *pipe = (struct pipe){0};

    int rc = ring_buf_init(&pipe->buf, PIPE_BUF);
    if (IS_ERR(rc)) {
        kfree(pipe);
        return ERR_PTR(rc);
    }

    struct inode* inode = &pipe->inode;
    static const struct inode_ops iops = {
        .destroy = pipe_destroy,
    };
    static const struct file_ops fops = {
        .open = pipe_open,
        .close = pipe_close,
        .pread = pipe_pread,
        .pwrite = pipe_pwrite,
        .poll = pipe_poll,
    };
    inode->iops = &iops;
    inode->fops = &fops;
    inode->mode = S_IFIFO;
    inode->ref_count = 1;

    return inode;
}
