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
    struct spinlock ring_lock;
    _Atomic(size_t) num_readers;
    _Atomic(size_t) num_writers;
};

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

static bool wake_open(struct file* file, void* ctx) {
    (void)ctx;
    const struct pipe* pipe = ASSERT_PTR(pipe_from_file(file));
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
    file->private_data = pipe;

    if (is_fifo) {
        int rc = file_wait(file, wake_open, NULL);
        if (rc == -EAGAIN && (file->flags & O_ACCMODE) == O_WRONLY) {
            file->private_data = NULL;
            return -ENXIO;
        }
    }

    TAKE_PTR(pipe_inode);
    return 0;
}

static void pipe_close(struct file* file) {
    struct pipe* pipe = ASSERT_PTR(pipe_from_file(file));
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
}

static bool wake_read(struct file* file, void* ctx) {
    (void)ctx;
    struct pipe* pipe = ASSERT_PTR(pipe_from_file(file));

    if (pipe->num_writers == 0)
        return true;

    SCOPED_LOCK(spinlock, &pipe->ring_lock);
    return !ring_buf_is_empty(pipe->ring);
}

static ssize_t pipe_pread(struct file* file, void* user_buffer, size_t count,
                          uint64_t offset) {
    (void)offset;

    struct pipe* pipe = ASSERT_PTR(pipe_from_file(file));
    size_t nread = 0;
    unsigned char* user_dest = user_buffer;
    while (count > 0) {
        int rc = file_wait(file, wake_read, NULL);
        if (nread > 0 && (rc == -EAGAIN || rc == -EINTR))
            break;
        if (IS_ERR(rc))
            return rc;

        for (;;) {
            // Ensure atomicity for reads <= PIPE_BUF
            char buf[PIPE_BUF];
            size_t n = 0;
            {
                SCOPED_LOCK(spinlock, &pipe->ring_lock);
                n = ring_buf_read(pipe->ring, buf, MIN(count, sizeof(buf)));
            }
            if (n == 0)
                break;
            if (copy_to_user(user_dest, buf, n))
                return -EFAULT;
            nread += n;
            user_dest += n;
            count -= n;
        }
        if (nread > 0)
            break;

        if (pipe->num_writers == 0)
            return 0;
    }
    return nread;
}

static bool wake_write(struct file* file, void* ctx) {
    struct pipe* pipe = ASSERT_PTR(pipe_from_file(file));
    size_t requested_capacity = *(const size_t*)ctx;

    if (pipe->num_readers == 0)
        return true;

    SCOPED_LOCK(spinlock, &pipe->ring_lock);
    return ring_buf_remaining_capacity(pipe->ring) >= requested_capacity;
}

static ssize_t pipe_pwrite(struct file* file, const void* user_buffer,
                           size_t count, uint64_t offset) {
    (void)offset;

    bool atomic = count <= PIPE_BUF;
    struct pipe* pipe = ASSERT_PTR(pipe_from_file(file));
    size_t nwritten = 0;
    const unsigned char* user_src = user_buffer;
    while (count > 0) {
        size_t requested_capacity = atomic ? count : 1;
        int rc = file_wait(file, wake_write, &requested_capacity);
        if (nwritten > 0 && (rc == -EAGAIN || rc == -EINTR))
            break;
        if (IS_ERR(rc))
            return rc;

        if (pipe->num_readers == 0) {
            rc = signal_send_to_tasks(0, current->tid, SIGPIPE);
            if (IS_ERR(rc))
                return rc;
            if (nwritten > 0)
                break;
            return -EPIPE;
        }

        size_t to_write = MIN(count, PIPE_BUF);
        char buf[PIPE_BUF];
        if (copy_from_user(buf, user_src, to_write))
            return -EFAULT;

        size_t n = 0;
        {
            SCOPED_LOCK(spinlock, &pipe->ring_lock);
            if (!atomic || ring_buf_remaining_capacity(pipe->ring) >= to_write)
                n = ring_buf_write(pipe->ring, buf, to_write);
        }
        nwritten += n;
        user_src += n;
        count -= n;
    }
    return nwritten;
}

static short pipe_poll(struct file* file, short events) {
    short revents = 0;
    struct pipe* pipe = pipe_from_file(file);
    {
        SCOPED_LOCK(spinlock, &pipe->ring_lock);
        if ((events & POLLIN) && !ring_buf_is_empty(pipe->ring))
            revents |= POLLIN;
        if ((events & POLLOUT) && !ring_buf_is_full(pipe->ring))
            revents |= POLLOUT;
    }
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

        struct ring_buf* new_ring FREE(ring_buf) =
            ASSERT(ring_buf_create(new_capacity));
        if (IS_ERR(new_ring))
            return PTR_ERR(new_ring);

        struct ring_buf* old_ring FREE(ring_buf) = NULL;
        {
            SCOPED_LOCK(spinlock, &pipe->ring_lock);

            if (ring_buf_size(pipe->ring) > new_capacity)
                return -EBUSY;

            while (!ring_buf_is_empty(pipe->ring)) {
                char buf[PAGE_SIZE];
                size_t n = ring_buf_read(pipe->ring, buf, sizeof(buf));
                ASSERT(ring_buf_write(new_ring, buf, n) == n);
            }

            old_ring = pipe->ring;
            pipe->ring = TAKE_PTR(new_ring);
        }

        return new_capacity;
    }
    case F_GETPIPE_SZ: {
        SCOPED_LOCK(spinlock, &pipe->ring_lock);
        return ring_buf_capacity(pipe->ring);
    }
    default:
        return -EINVAL;
    }
}
