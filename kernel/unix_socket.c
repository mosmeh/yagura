#include "api/err.h"
#include "api/stat.h"
#include "fs/fs.h"
#include "kmalloc.h"
#include "lock.h"
#include "panic.h"
#include "scheduler.h"
#include "socket.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>

#define BUF_CAPACITY 1024

typedef struct locked_buf {
    mutex lock;
    void* inner_buf;
    atomic_size_t size;
    size_t offset;
} locked_buf;

static int locked_buf_init(locked_buf* buf) {
    memset(buf, 0, sizeof(locked_buf));
    mutex_init(&buf->lock);
    atomic_init(&buf->size, 0);
    buf->inner_buf = kmalloc(BUF_CAPACITY);
    if (!buf->inner_buf)
        return -ENOMEM;
    return 0;
}

typedef struct unix_socket {
    struct file base_file;
    int backlog;

    mutex pending_queue_lock;
    atomic_size_t num_pending;
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

static bool read_should_unblock(atomic_size_t* size) {
    return atomic_load_explicit(size, memory_order_acquire) > 0;
}

static ssize_t unix_socket_read(file_description* desc, void* buffer,
                                size_t count) {
    unix_socket* socket = (unix_socket*)desc->file;
    locked_buf* buf = get_buf_to_read(socket, desc);

    if (atomic_load_explicit(&buf->size, memory_order_acquire) == 0)
        scheduler_block(read_should_unblock, &buf->size);

    mutex_lock(&buf->lock);

    if (buf->offset + count >= buf->size)
        count = buf->size - buf->offset;
    memcpy(buffer, (void*)((uintptr_t)buf->inner_buf + buf->offset), count);
    buf->offset += count;

    if (buf->offset >= buf->size)
        buf->size = buf->offset = 0;

    mutex_unlock(&buf->lock);
    return count;
}

static bool write_should_unblock(atomic_size_t* size) {
    return atomic_load_explicit(size, memory_order_acquire) == 0;
}

static ssize_t unix_socket_write(file_description* desc, const void* buffer,
                                 size_t count) {
    unix_socket* socket = (unix_socket*)desc->file;
    locked_buf* buf = get_buf_to_write(socket, desc);

    if (atomic_load_explicit(&buf->size, memory_order_acquire) > 0)
        scheduler_block(write_should_unblock, &buf->size);

    mutex_lock(&buf->lock);

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

    atomic_init(&socket->num_pending, 0);
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
    mutex_lock(&listener->pending_queue_lock);

    if (listener->next) {
        unix_socket* it = listener->next;
        while (it->next)
            it = it->next;
        it->next = connector;
    } else {
        listener->next = connector;
    }

    mutex_unlock(&listener->pending_queue_lock);
    atomic_fetch_add_explicit(&listener->num_pending, 1, memory_order_acq_rel);
}

static unix_socket* deque_pending(unix_socket* listener) {
    mutex_lock(&listener->pending_queue_lock);

    unix_socket* connector = listener->next;
    listener->next = connector->next;

    mutex_unlock(&listener->pending_queue_lock);
    atomic_fetch_sub_explicit(&listener->num_pending, 1, memory_order_acq_rel);

    ASSERT(connector);
    return connector;
}

static bool accept_should_unblock(atomic_size_t* num_pending) {
    return atomic_load_explicit(num_pending, memory_order_acquire) > 0;
}

unix_socket* unix_socket_accept(unix_socket* listener) {
    if (atomic_load_explicit(&listener->num_pending, memory_order_acquire) == 0)
        scheduler_block(accept_should_unblock, &listener->num_pending);

    unix_socket* connector = deque_pending(listener);
    ASSERT(!atomic_exchange_explicit(&connector->connected, true,
                                     memory_order_acq_rel));
    return connector;
}

static bool connect_should_unblock(atomic_bool* connected) {
    return atomic_load_explicit(connected, memory_order_acquire);
}

int unix_socket_connect(file_description* connector_fd, unix_socket* listener) {
    unix_socket* connector = (unix_socket*)connector_fd->file;
    connector->connector_fd = connector_fd;

    if (atomic_load_explicit(&listener->num_pending, memory_order_acquire) >=
        (size_t)listener->backlog)
        return -ECONNREFUSED;
    enqueue_pending(listener, connector);

    scheduler_block(connect_should_unblock, &connector->connected);
    return 0;
}
