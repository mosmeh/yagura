#include "api/err.h"
#include "api/stat.h"
#include "fs/fs.h"
#include "kmalloc.h"
#include "lock.h"
#include "panic.h"
#include "scheduler.h"
#include "socket.h"
#include <stdbool.h>
#include <string.h>

#define BUF_CAPACITY 1024

typedef struct locked_buf {
    mutex lock;
    void* inner_buf;
    size_t size;
    size_t offset;
} locked_buf;

static int locked_buf_init(locked_buf* buf) {
    memset(buf, 0, sizeof(locked_buf));
    mutex_init(&buf->lock);
    buf->inner_buf = kmalloc(BUF_CAPACITY);
    if (!buf->inner_buf)
        return -ENOMEM;
    return 0;
}

typedef struct unix_socket {
    struct file base_file;
    int backlog;

    mutex pending_queue_lock;
    size_t num_pending;
    struct unix_socket* next; // pending queue

    atomic_bool connected;
    file_description* connector_fd;

    locked_buf server_to_client_buf;
    locked_buf client_to_server_buf;
} unix_socket;

static locked_buf* get_buf_to_read(unix_socket* socket,
                                   file_description* desc) {
    bool is_client = socket->connector_fd == desc;
    return is_client ? &socket->server_to_client_buf
                     : &socket->client_to_server_buf;
}

static locked_buf* get_buf_to_write(unix_socket* socket,
                                    file_description* desc) {
    bool is_client = socket->connector_fd == desc;
    return is_client ? &socket->client_to_server_buf
                     : &socket->server_to_client_buf;
}

static ssize_t unix_socket_read(file_description* desc, void* buffer,
                                size_t count) {
    unix_socket* socket = (unix_socket*)desc->file;
    locked_buf* buf = get_buf_to_read(socket, desc);

    for (;;) {
        mutex_lock(&buf->lock);
        if (buf->size > 0)
            break;
        mutex_unlock(&buf->lock);
        scheduler_yield(true);
    }

    if (buf->offset + count >= buf->size)
        count = buf->size - buf->offset;
    memcpy(buffer, (void*)((uintptr_t)buf->inner_buf + buf->offset), count);
    buf->offset += count;

    if (buf->offset >= buf->size)
        buf->size = buf->offset = 0;

    mutex_unlock(&buf->lock);
    return count;
}

static ssize_t unix_socket_write(file_description* desc, const void* buffer,
                                 size_t count) {
    unix_socket* socket = (unix_socket*)desc->file;
    locked_buf* buf = get_buf_to_write(socket, desc);

    for (;;) {
        mutex_lock(&buf->lock);
        if (buf->size == 0)
            break;
        mutex_unlock(&buf->lock);
        scheduler_yield(true);
    }

    if (count >= BUF_CAPACITY)
        count = BUF_CAPACITY - buf->offset;
    memcpy(buf->inner_buf, buffer, count);
    buf->offset = 0;
    buf->size = count;

    mutex_unlock(&buf->lock);
    return count;
}

unix_socket* unix_socket_create(void) {
    unix_socket* socket = kmalloc(sizeof(unix_socket));
    if (!socket)
        return ERR_PTR(-ENOMEM);
    memset(socket, 0, sizeof(unix_socket));

    struct file* file = &socket->base_file;
    file->mode = S_IFSOCK;
    file->read = unix_socket_read;
    file->write = unix_socket_write;

    mutex_init(&socket->pending_queue_lock);
    atomic_init(&socket->connected, false);

    int rc = locked_buf_init(&socket->client_to_server_buf);
    if (IS_ERR(rc))
        return ERR_PTR(rc);
    rc = locked_buf_init(&socket->server_to_client_buf);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    return socket;
}

void unix_socket_set_backlog(unix_socket* socket, int backlog) {
    socket->backlog = backlog;
}

static void enqueue_pending(unix_socket* listener, unix_socket* connector) {
    connector->next = NULL;
    if (listener->next) {
        unix_socket* it = listener->next;
        while (it->next)
            it = it->next;
        it->next = connector;
    } else {
        listener->next = connector;
    }
    ++listener->num_pending;
}

static unix_socket* deque_pending(unix_socket* listener) {
    unix_socket* connector = listener->next;
    listener->next = connector->next;
    --listener->num_pending;
    return connector;
}

unix_socket* unix_socket_accept(unix_socket* listener) {
    for (;;) {
        mutex_lock(&listener->pending_queue_lock);
        if (listener->num_pending > 0)
            break;
        mutex_unlock(&listener->pending_queue_lock);
        scheduler_yield(true);
    }

    unix_socket* connector = deque_pending(listener);
    mutex_unlock(&listener->pending_queue_lock);

    ASSERT(!atomic_exchange_explicit(&connector->connected, true,
                                     memory_order_acq_rel));
    return connector;
}

int unix_socket_connect(file_description* connector_fd, unix_socket* listener) {
    unix_socket* connector = (unix_socket*)connector_fd->file;
    connector->connector_fd = connector_fd;

    mutex_lock(&listener->pending_queue_lock);
    if (listener->num_pending >= (size_t)listener->backlog) {
        mutex_unlock(&listener->pending_queue_lock);
        return -ECONNREFUSED;
    }
    enqueue_pending(listener, connector);
    mutex_unlock(&listener->pending_queue_lock);

    while (!atomic_load_explicit(&connector->connected, memory_order_acquire))
        scheduler_yield(true);

    return 0;
}
