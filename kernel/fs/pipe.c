#include "private.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/signal.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/poll.h>
#include <kernel/containers/ring_buf.h>
#include <kernel/device/device.h>
#include <kernel/fs/file.h>
#include <kernel/panic.h>
#include <kernel/task.h>

struct pipe {
    struct inode vfs_inode;
    struct ring_buf* buf;
    atomic_size_t num_readers;
    atomic_size_t num_writers;
};

static struct slab pipe_slab;
static struct mount* pipe_mount;

void pipe_init(void) {
    slab_init(&pipe_slab, "pipe", sizeof(struct pipe));

    static struct file_system pipe_fs = {
        .name = "pipefs",
        .flags = FILE_SYSTEM_KERNEL_ONLY,
    };
    ASSERT_OK(file_system_register(&pipe_fs));

    pipe_mount = file_system_mount(&pipe_fs, "pipefs");
    ASSERT_PTR(pipe_mount);
}

static void pipe_lock(struct pipe* pipe) { inode_lock(&pipe->vfs_inode); }

static void pipe_unlock(struct pipe* pipe) { inode_unlock(&pipe->vfs_inode); }

static struct pipe* pipe_from_inode(struct inode* inode) {
    return CONTAINER_OF(inode, struct pipe, vfs_inode);
}

static void pipe_destroy(struct inode* inode) {
    struct pipe* pipe = pipe_from_inode(inode);
    ring_buf_destroy(pipe->buf);
    slab_free(&pipe_slab, pipe);
}

static struct pipe* pipe_from_file(struct file* file) {
    return file->private_data;
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
    bool is_fifo = false;
    struct inode* pipe_inode;
    if (file->inode->mount == pipe_mount) {
        // Anonymous pipe
        pipe_inode = file->inode;
    } else {
        // Named pipe (FIFO)
        is_fifo = true;
        pipe_inode = file->inode->pipe;
        if (!pipe_inode) {
            struct inode* new_pipe = pipe_create();
            if (IS_ERR(ASSERT(new_pipe)))
                return PTR_ERR(new_pipe);
            struct inode* expected = NULL;
            if (atomic_compare_exchange_strong(&file->inode->pipe, &expected,
                                               new_pipe)) {
                pipe_inode = new_pipe;
            } else {
                inode_unref(new_pipe);
                pipe_inode = expected;
            }
        }
    }
    inode_ref(pipe_inode);

    int rc = 0;
    struct pipe* pipe = pipe_from_inode(pipe_inode);
    switch (file->flags & O_ACCMODE) {
    case O_RDONLY:
        ++pipe->num_readers;
        break;
    case O_WRONLY:
        ++pipe->num_writers;
        break;
    default:
        rc = -EINVAL;
        goto fail;
    }
    file->private_data = pipe;

    if (is_fifo) {
        rc = file_block(file, unblock_open, 0);
        if (rc == -EAGAIN && (file->flags & O_ACCMODE) == O_WRONLY) {
            rc = -ENXIO;
            file->private_data = NULL;
            goto fail;
        }
    }

    return rc;

fail:
    inode_unref(&pipe->vfs_inode);
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
    inode_unref(&pipe->vfs_inode);
    return 0;
}

static bool unblock_read(struct file* file) {
    const struct pipe* pipe = pipe_from_file(file);
    return pipe->num_writers == 0 || !ring_buf_is_empty(pipe->buf);
}

static ssize_t pipe_pread(struct file* file, void* user_buffer, size_t count,
                          uint64_t offset) {
    (void)offset;

    struct pipe* pipe = pipe_from_file(file);
    struct ring_buf* buf = pipe->buf;

    for (;;) {
        int rc = file_block(file, unblock_read, 0);
        if (IS_ERR(rc))
            return rc;

        pipe_lock(pipe);
        if (!ring_buf_is_empty(buf)) {
            ssize_t nread = ring_buf_read_to_user(buf, user_buffer, count);
            pipe_unlock(pipe);
            return nread;
        }

        bool no_writer = pipe->num_writers == 0;
        pipe_unlock(pipe);
        if (no_writer)
            return 0;
    }
}

static bool unblock_write(struct file* file) {
    const struct pipe* pipe = pipe_from_file(file);
    return pipe->num_readers == 0 || !ring_buf_is_full(pipe->buf);
}

static ssize_t pipe_pwrite(struct file* file, const void* user_buffer,
                           size_t count, uint64_t offset) {
    (void)offset;

    struct pipe* pipe = pipe_from_file(file);
    struct ring_buf* buf = pipe->buf;

    for (;;) {
        int rc = file_block(file, unblock_write, 0);
        if (IS_ERR(rc))
            return rc;

        pipe_lock(pipe);
        if (pipe->num_readers == 0) {
            pipe_unlock(pipe);
            int rc = task_send_signal(current->tid, SIGPIPE, 0);
            if (IS_ERR(rc))
                return rc;
            return -EPIPE;
        }

        if (ring_buf_is_full(buf)) {
            pipe_unlock(pipe);
            continue;
        }

        ssize_t nwritten = ring_buf_write_from_user(buf, user_buffer, count);
        pipe_unlock(pipe);
        return nwritten;
    }
}

static short pipe_poll(struct file* file, short events) {
    short revents = 0;
    const struct pipe* pipe = pipe_from_file(file);
    if ((events & POLLIN) && !ring_buf_is_empty(pipe->buf))
        revents |= POLLIN;
    if ((events & POLLOUT) && !ring_buf_is_full(pipe->buf))
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

const struct file_ops pipe_fops = {
    .open = pipe_open,
    .close = pipe_close,
    .pread = pipe_pread,
    .pwrite = pipe_pwrite,
    .poll = pipe_poll,
};

static _Atomic(ino_t) next_ino = 1;

struct inode* pipe_create(void) {
    struct pipe* pipe = slab_alloc(&pipe_slab);
    if (IS_ERR(ASSERT(pipe)))
        return ERR_CAST(pipe);
    *pipe = (struct pipe){
        .vfs_inode = INODE_INIT,
    };

    int rc = 0;

    pipe->buf = ring_buf_create(PIPE_BUF);
    if (IS_ERR(pipe->buf)) {
        rc = PTR_ERR(pipe->buf);
        pipe->buf = NULL;
        goto fail;
    }

    struct inode* inode = &pipe->vfs_inode;
    inode->ino = atomic_fetch_add(&next_ino, 1);
    static const struct inode_ops iops = {
        .destroy = pipe_destroy,
    };
    inode->iops = &iops;
    inode->fops = &pipe_fops;
    inode->mode = S_IFIFO;

    rc = mount_commit_inode(pipe_mount, inode);
    if (IS_ERR(rc)) {
        inode_unref(inode);
        goto fail;
    }

    return inode;

fail:
    ring_buf_destroy(pipe->buf);
    slab_free(&pipe_slab, pipe);
    return ERR_PTR(rc);
}
