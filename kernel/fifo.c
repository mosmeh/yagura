#include "api/fcntl.h"
#include "api/signum.h"
#include "fs/fs.h"
#include "memory/memory.h"
#include "panic.h"
#include "process.h"
#include "ring_buf.h"
#include "scheduler.h"
#include "system.h"

#define BUF_CAPACITY 1024

struct fifo {
    struct file base_file;
    ring_buf buf;
    atomic_size_t num_readers;
    atomic_size_t num_writers;
};

static int fifo_open(struct file* file, int flags, mode_t mode) {
    (void)flags;
    (void)mode;
    if ((flags & O_RDONLY) && (flags & O_WRONLY))
        return -EINVAL;
    struct fifo* fifo = (struct fifo*)file;
    if (flags & O_RDONLY)
        atomic_fetch_add_explicit(&fifo->num_readers, 1, memory_order_acq_rel);
    if (flags & O_WRONLY)
        atomic_fetch_add_explicit(&fifo->num_writers, 1, memory_order_acq_rel);
    return 0;
}

static int fifo_close(file_description* desc) {
    ASSERT(!((desc->flags & O_RDONLY) && (desc->flags & O_WRONLY)));
    struct fifo* fifo = (struct fifo*)desc->file;
    if (desc->flags & O_RDONLY)
        atomic_fetch_sub_explicit(&fifo->num_readers, 1, memory_order_acq_rel);
    if (desc->flags & O_WRONLY)
        atomic_fetch_sub_explicit(&fifo->num_writers, 1, memory_order_acq_rel);
    return 0;
}

static bool read_should_unblock(file_description* desc) {
    const struct fifo* fifo = (const struct fifo*)desc->file;
    bool no_writer =
        atomic_load_explicit(&fifo->num_writers, memory_order_acquire) == 0;
    return no_writer || !ring_buf_is_empty(&fifo->buf);
}

static ssize_t fifo_read(file_description* desc, void* buffer, size_t count) {
    struct fifo* fifo = (struct fifo*)desc->file;
    ring_buf* buf = &fifo->buf;
    int rc = fs_block(desc, read_should_unblock);
    if (IS_ERR(rc))
        return rc;

    mutex_lock(&buf->lock);
    bool no_writer =
        atomic_load_explicit(&fifo->num_writers, memory_order_acquire) == 0;
    if (no_writer && ring_buf_is_empty(buf)) {
        mutex_unlock(&buf->lock);
        return 0;
    }
    ssize_t nread = ring_buf_read(buf, buffer, count);
    mutex_unlock(&buf->lock);

    return nread;
}

static bool write_should_unblock(struct file_description* desc) {
    struct fifo* fifo = (struct fifo*)desc->file;
    bool no_reader =
        atomic_load_explicit(&fifo->num_readers, memory_order_acquire) == 0;
    return no_reader || !ring_buf_is_full(&fifo->buf);
}

static ssize_t fifo_write(file_description* desc, const void* buffer,
                          size_t count) {
    struct fifo* fifo = (struct fifo*)desc->file;
    ring_buf* buf = &fifo->buf;
    int rc = fs_block(desc, write_should_unblock);
    if (IS_ERR(rc))
        return rc;

    mutex_lock(&buf->lock);
    if (atomic_load_explicit(&fifo->num_readers, memory_order_acquire) == 0) {
        mutex_unlock(&buf->lock);
        int rc = process_send_signal_to_one(current->pid, SIGPIPE);
        if (IS_ERR(rc))
            return rc;
        return -EPIPE;
    }

    if (ring_buf_is_full(buf)) {
        mutex_unlock(&buf->lock);
        return 0;
    }

    ssize_t nwritten = ring_buf_write(buf, buffer, count);
    mutex_unlock(&buf->lock);

    return nwritten;
}

struct fifo* fifo_create(void) {
    struct fifo* fifo = kmalloc(sizeof(struct fifo));
    if (!fifo)
        return ERR_PTR(-ENOMEM);
    *fifo = (struct fifo){0};

    atomic_init(&fifo->num_readers, 0);
    atomic_init(&fifo->num_writers, 0);

    int rc = ring_buf_init(&fifo->buf);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    struct file* file = &fifo->base_file;
    file->name = kstrdup("fifo");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    static file_ops fops = {.open = fifo_open,
                            .close = fifo_close,
                            .read = fifo_read,
                            .write = fifo_write};
    file->fops = &fops;
    file->mode = S_IFIFO;

    return fifo;
}
