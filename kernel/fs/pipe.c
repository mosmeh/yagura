#include "private.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/signal.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/poll.h>
#include <kernel/containers/ring_buf.h>
#include <kernel/device/device.h>
#include <kernel/fs/file.h>
#include <kernel/fs/vfs.h>
#include <kernel/panic.h>
#include <kernel/task/signal.h>
#include <kernel/task/task.h>

#define PIPE_DEF_BUFFERS 16

struct pipe {
    struct inode vfs_inode;
    struct ring_buf* ring;
    size_t num_readers;
    size_t num_writers;
    struct waitqueue wait;
};

DEFINE_LOCKED(pipe, struct pipe, inode, vfs_inode)

static struct slab pipe_slab;
static struct mount* pipe_mount;

void pipe_init(void) {
    SLAB_INIT_FOR_TYPE(&pipe_slab, "pipe", struct pipe);

    static struct file_system pipe_fs = {
        .name = "pipefs",
        .flags = FILE_SYSTEM_KERNEL_ONLY,
    };
    ASSERT_OK(file_system_register(&pipe_fs));

    pipe_mount = ASSERT_PTR(file_system_mount(&pipe_fs, "pipefs"));
}

static struct pipe* pipe_from_inode(struct inode* inode) {
    return CONTAINER_OF(inode, struct pipe, vfs_inode);
}

static void pipe_destroy(struct inode* inode) {
    struct pipe* pipe = pipe_from_inode(inode);
    ring_buf_destroy(pipe->ring);
    slab_free(&pipe_slab, pipe);
}

static struct pipe* pipe_from_file(struct file* file) {
    if (file->fops != &pipe_fops)
        return NULL;
    return file->private_data;
}

static int pipe_open(struct file* file) {
    bool is_fifo = false;
    struct inode* pipe_inode FREE(inode) = NULL;
    if (file->inode->mount == pipe_mount) {
        // Anonymous pipe
        pipe_inode = file->inode;
    } else {
        // Named pipe (FIFO)
        is_fifo = true;
        pipe_inode = file->inode->pipe;
        if (!pipe_inode) {
            struct inode* new_pipe = ASSERT(pipe_create());
            if (IS_ERR(new_pipe))
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

    struct pipe* pipe = pipe_from_inode(pipe_inode);

    {
        SCOPED_LOCK(pipe, pipe);
        switch (file->flags & O_ACCMODE) {
        case O_RDONLY:
            ++pipe->num_readers;
            if (is_fifo && !(file->flags & O_NONBLOCK)) {
                for (;;) {
                    SCOPED_WAIT(waiter, &pipe->wait, TASK_INTERRUPTIBLE);
                    if (pipe->num_writers > 0)
                        break;
                    pipe_unlock(pipe);
                    int rc = waiter_wait_interruptible(&waiter);
                    pipe_lock(pipe);
                    if (IS_ERR(rc)) {
                        --pipe->num_readers;
                        return rc;
                    }
                }
            }
            break;
        case O_WRONLY:
            ++pipe->num_writers;
            if (is_fifo) {
                for (;;) {
                    SCOPED_WAIT(waiter, &pipe->wait, TASK_INTERRUPTIBLE);
                    if (pipe->num_readers > 0)
                        break;
                    if (file->flags & O_NONBLOCK) {
                        --pipe->num_writers;
                        return -ENXIO;
                    }
                    pipe_unlock(pipe);
                    int rc = waiter_wait_interruptible(&waiter);
                    pipe_lock(pipe);
                    if (IS_ERR(rc)) {
                        --pipe->num_writers;
                        return rc;
                    }
                }
            }
            break;
        case O_RDWR:
            ++pipe->num_readers;
            ++pipe->num_writers;
            break;
        default:
            UNREACHABLE();
        }
    }
    waitqueue_wake_all(&pipe->wait);

    file->private_data = pipe;
    TAKE_PTR(pipe_inode);
    return 0;
}

static void pipe_close(struct file* file) {
    struct pipe* pipe = ASSERT_PTR(pipe_from_file(file));
    {
        SCOPED_LOCK(pipe, pipe);
        switch (file->flags & O_ACCMODE) {
        case O_RDONLY:
            --pipe->num_readers;
            break;
        case O_WRONLY:
            --pipe->num_writers;
            break;
        case O_RDWR:
            --pipe->num_readers;
            --pipe->num_writers;
            break;
        default:
            UNREACHABLE();
        }
    }
    waitqueue_wake_all(&pipe->wait);
    inode_unref(&pipe->vfs_inode);
}

static ssize_t pipe_pread(struct file* file, void* user_buffer, size_t count,
                          uint64_t offset) {
    (void)offset;

    struct pipe* pipe = ASSERT_PTR(pipe_from_file(file));
    if (count == 0)
        return 0;
    for (;;) {
        for (;;) {
            pipe_lock(pipe);
            SCOPED_WAIT(waiter, &pipe->wait, TASK_INTERRUPTIBLE);
            if (!ring_buf_is_empty(pipe->ring))
                break;
            if (pipe->num_writers == 0) {
                pipe_unlock(pipe);
                return 0;
            }
            pipe_unlock(pipe);
            if (file->flags & O_NONBLOCK)
                return -EAGAIN;
            if (waiter_wait_interruptible(&waiter))
                return -EINTR;
        }
        ssize_t n = ring_buf_read_to_user(pipe->ring, user_buffer, count);
        pipe_unlock(pipe);
        if (IS_ERR(n))
            return n;
        if (n > 0) {
            waitqueue_wake_all(&pipe->wait);
            return n;
        }
    }
}

NODISCARD static ssize_t do_write(struct file* file, const void* user_src,
                                  size_t count, bool atomic) {
    struct pipe* pipe = ASSERT_PTR(pipe_from_file(file));
    for (;;) {
        pipe_lock(pipe);
        SCOPED_WAIT(waiter, &pipe->wait, TASK_INTERRUPTIBLE);
        if (pipe->num_readers == 0) {
            pipe_unlock(pipe);
            int rc = signal_send_to_tasks(0, current->tid, SIGPIPE);
            if (IS_ERR(rc))
                return rc;
            return -EPIPE;
        }
        if (ring_buf_remaining_capacity(pipe->ring) >= (atomic ? count : 1))
            break;
        pipe_unlock(pipe);
        if (file->flags & O_NONBLOCK)
            return -EAGAIN;
        if (waiter_wait_interruptible(&waiter))
            return -EINTR;
    }
    ssize_t n = 0;
    if (!atomic ||
        ring_buf_remaining_capacity(pipe->ring) >= MIN(count, PIPE_BUF))
        n = ring_buf_write_from_user(pipe->ring, user_src, count);
    pipe_unlock(pipe);
    return n;
}

static ssize_t pipe_pwrite(struct file* file, const void* user_buffer,
                           size_t count, uint64_t offset) {
    (void)offset;

    bool atomic = count <= PIPE_BUF;
    struct pipe* pipe = ASSERT_PTR(pipe_from_file(file));
    size_t nwritten = 0;
    const unsigned char* user_src = user_buffer;
    while (count > 0) {
        ssize_t n = do_write(file, user_src, count, atomic);
        if (IS_ERR(n)) {
            if (nwritten > 0)
                break;
            return n;
        }
        if (n > 0) {
            nwritten += n;
            user_src += n;
            count -= n;
            waitqueue_wake_all(&pipe->wait);
        }
    }
    return nwritten;
}

static short pipe_poll(struct file* file, short events) {
    short revents = 0;
    struct pipe* pipe = pipe_from_file(file);
    SCOPED_LOCK(pipe, pipe);
    if ((events & POLLIN) && !ring_buf_is_empty(pipe->ring))
        revents |= POLLIN;
    if ((events & POLLOUT) && !ring_buf_is_full(pipe->ring))
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
    case O_RDWR:
        ASSERT(pipe->num_readers > 0);
        ASSERT(pipe->num_writers > 0);
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
    struct pipe* pipe = ASSERT(slab_alloc(&pipe_slab));
    if (IS_ERR(pipe))
        return ERR_CAST(pipe);
    *pipe = (struct pipe){
        .vfs_inode = INODE_INIT,
    };

    struct ring_buf* ring =
        ASSERT(ring_buf_create(PIPE_DEF_BUFFERS << PAGE_SHIFT));
    if (IS_ERR(ring)) {
        slab_free(&pipe_slab, pipe);
        return ERR_CAST(ring);
    }
    pipe->ring = ring;

    struct inode* inode = &pipe->vfs_inode;
    inode->ino = atomic_fetch_add(&next_ino, 1);
    static const struct inode_ops iops = {
        .destroy = pipe_destroy,
    };
    inode->iops = &iops;
    inode->fops = &pipe_fops;
    inode->mode = S_IFIFO | S_IRUSR | S_IWUSR;

    int rc = mount_commit_inode(pipe_mount, inode);
    if (IS_ERR(rc)) {
        inode_unref(inode);
        return ERR_PTR(rc);
    }

    return inode;
}

int pipe_fcntl(struct file* file, int cmd, unsigned long arg) {
    struct pipe* pipe = pipe_from_file(file);
    if (!pipe)
        return -EBADF;

    switch (cmd) {
    case F_SETPIPE_SZ: {
        if (arg > (1UL << 31))
            return -EINVAL;
        size_t new_capacity = next_power_of_two(MAX(arg, PAGE_SIZE));
        if (new_capacity < PAGE_SIZE || new_capacity < arg)
            return -EINVAL;

        {
            SCOPED_LOCK(pipe, pipe);
            if (ring_buf_size(pipe->ring) > new_capacity)
                return -EBUSY;

            struct ring_buf* new_ring FREE(ring_buf) =
                ASSERT(ring_buf_create(new_capacity));
            if (IS_ERR(new_ring))
                return PTR_ERR(new_ring);

            while (!ring_buf_is_empty(pipe->ring)) {
                char buf[PAGE_SIZE];
                size_t n = ring_buf_read(pipe->ring, buf, sizeof(buf));
                ASSERT(ring_buf_write(new_ring, buf, n) == n);
            }

            ring_buf_destroy(pipe->ring);
            pipe->ring = TAKE_PTR(new_ring);
        }

        waitqueue_wake_all(&pipe->wait);

        return new_capacity;
    }
    case F_GETPIPE_SZ: {
        SCOPED_LOCK(pipe, pipe);
        return ring_buf_capacity(pipe->ring);
    }
    default:
        return -EINVAL;
    }
}
