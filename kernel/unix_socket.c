#include "api/err.h"
#include "api/stat.h"
#include "fs/fs.h"
#include "kmalloc.h"
#include "lock.h"
#include "panic.h"
#include "process.h"
#include "socket.h"
#include <common/string.h>
#include <stdbool.h>

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
    file_description* connect_side_fd;

    locked_buf server_to_client_buf;
    locked_buf client_to_server_buf;
} unix_socket;

static locked_buf* get_buf_to_read(unix_socket* socket,
                                   file_description* desc) {
    bool is_client = socket->connect_side_fd == desc;
    return is_client ? &socket->server_to_client_buf
                     : &socket->client_to_server_buf;
}

static locked_buf* get_buf_to_write(unix_socket* socket,
                                    file_description* desc) {
    bool is_client = socket->connect_side_fd == desc;
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
        process_switch();
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
        process_switch();
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

static void enqueue_pending(unix_socket* listening, unix_socket* connecting) {
    connecting->next = NULL;
    if (listening->next) {
        unix_socket* it = listening->next;
        while (it->next)
            it = it->next;
        it->next = connecting;
    } else {
        listening->next = connecting;
    }
    ++listening->num_pending;
}

static unix_socket* deque_pending(unix_socket* listening) {
    unix_socket* connecting = listening->next;
    listening->next = connecting->next;
    --listening->num_pending;
    return connecting;
}

unix_socket* unix_socket_accept(unix_socket* listening) {
    for (;;) {
        mutex_lock(&listening->pending_queue_lock);
        if (listening->num_pending > 0)
            break;
        mutex_unlock(&listening->pending_queue_lock);
        process_switch();
    }

    unix_socket* connecting = deque_pending(listening);
    mutex_unlock(&listening->pending_queue_lock);

    KASSERT(!atomic_exchange_explicit(&connecting->connected, true,
                                      memory_order_acq_rel));
    return connecting;
}

int unix_socket_connect(file_description* connecting_fd,
                        unix_socket* listening) {
    unix_socket* connecting = (unix_socket*)connecting_fd->file;
    connecting->connect_side_fd = connecting_fd;

    mutex_lock(&listening->pending_queue_lock);
    if (listening->num_pending >= (size_t)listening->backlog) {
        mutex_unlock(&listening->pending_queue_lock);
        return -ECONNREFUSED;
    }
    enqueue_pending(listening, connecting);
    mutex_unlock(&listening->pending_queue_lock);

    while (!atomic_load_explicit(&connecting->connected, memory_order_acquire))
        process_switch();

    return 0;
}
