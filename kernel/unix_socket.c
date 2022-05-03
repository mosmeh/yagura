#include "memory/memory.h"
#include "panic.h"
#include "scheduler.h"
#include "socket.h"

static ring_buf* get_buf_to_read(unix_socket* socket, file_description* desc) {
    bool is_client = socket->connector_fd == desc;
    return is_client ? &socket->server_to_client_buf
                     : &socket->client_to_server_buf;
}

static ring_buf* get_buf_to_write(unix_socket* socket, file_description* desc) {
    bool is_client = socket->connector_fd == desc;
    return is_client ? &socket->client_to_server_buf
                     : &socket->server_to_client_buf;
}

static bool read_should_unblock(file_description* desc) {
    unix_socket* socket = (unix_socket*)desc->file;
    ring_buf* buf = get_buf_to_read(socket, desc);
    return !ring_buf_is_empty(buf);
}

static ssize_t unix_socket_read(file_description* desc, void* buffer,
                                size_t count) {
    unix_socket* socket = (unix_socket*)desc->file;
    ring_buf* buf = get_buf_to_read(socket, desc);
    int rc = fs_block(desc, read_should_unblock);
    if (IS_ERR(rc))
        return rc;

    mutex_lock(&buf->lock);
    if (ring_buf_is_empty(buf)) {
        mutex_unlock(&buf->lock);
        return 0;
    }
    ssize_t nread = ring_buf_read(buf, buffer, count);
    mutex_unlock(&buf->lock);
    return nread;
}

static bool write_should_unblock(file_description* desc) {
    unix_socket* socket = (unix_socket*)desc->file;
    ring_buf* buf = get_buf_to_write(socket, desc);
    return !ring_buf_is_full(buf);
}

static ssize_t unix_socket_write(file_description* desc, const void* buffer,
                                 size_t count) {
    unix_socket* socket = (unix_socket*)desc->file;
    ring_buf* buf = get_buf_to_write(socket, desc);
    int rc = fs_block(desc, write_should_unblock);
    if (IS_ERR(rc))
        return rc;

    mutex_lock(&buf->lock);
    if (ring_buf_is_full(buf)) {
        mutex_unlock(&buf->lock);
        return 0;
    }
    ssize_t nwritten = ring_buf_write(buf, buffer, count);
    mutex_unlock(&buf->lock);
    return nwritten;
}

unix_socket* unix_socket_create(void) {
    unix_socket* socket = kmalloc(sizeof(unix_socket));
    if (!socket)
        return ERR_PTR(-ENOMEM);
    *socket = (unix_socket){0};

    struct file* file = &socket->base_file;
    file->mode = S_IFSOCK;
    file->read = unix_socket_read;
    file->write = unix_socket_write;

    atomic_init(&socket->num_pending, 0);
    mutex_init(&socket->pending_queue_lock);
    atomic_init(&socket->connected, false);

    int rc = ring_buf_init(&socket->client_to_server_buf);
    if (IS_ERR(rc))
        return ERR_PTR(rc);
    rc = ring_buf_init(&socket->server_to_client_buf);
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
    int rc = scheduler_block(accept_should_unblock, &listener->num_pending);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

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

    return scheduler_block(connect_should_unblock, &connector->connected);
}
