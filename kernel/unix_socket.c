#include "api/signum.h"
#include "api/sys/poll.h"
#include "api/sys/socket.h"
#include "memory/memory.h"
#include "panic.h"
#include "process.h"
#include "socket.h"

static void unix_socket_destroy_inode(struct inode* inode) {
    unix_socket* socket = (unix_socket*)inode;
    ring_buf_destroy(&socket->to_connector_buf);
    ring_buf_destroy(&socket->to_acceptor_buf);
    kfree(socket);
}

static int unix_socket_close(file_description* desc) {
    unix_socket* socket = (unix_socket*)desc->inode;
    socket->is_open_for_writing_to_connector = false;
    socket->is_open_for_writing_to_acceptor = false;
    return 0;
}

static bool is_connector(file_description* desc) {
    unix_socket* socket = (unix_socket*)desc->inode;
    return socket->connector_fd == desc;
}

static bool is_open_for_reading(file_description* desc) {
    unix_socket* socket = (unix_socket*)desc->inode;
    return is_connector(desc) ? socket->is_open_for_writing_to_connector
                              : socket->is_open_for_writing_to_acceptor;
}

static ring_buf* buf_to_read(file_description* desc) {
    unix_socket* socket = (unix_socket*)desc->inode;
    return is_connector(desc) ? &socket->to_connector_buf
                              : &socket->to_acceptor_buf;
}

static ring_buf* buf_to_write(file_description* desc) {
    unix_socket* socket = (unix_socket*)desc->inode;
    return is_connector(desc) ? &socket->to_acceptor_buf
                              : &socket->to_connector_buf;
}

static bool is_readable(file_description* desc) {
    if (!is_open_for_reading(desc))
        return true;
    ring_buf* buf = buf_to_read(desc);
    return !ring_buf_is_empty(buf);
}

static ssize_t unix_socket_read(file_description* desc, void* buffer,
                                size_t count) {
    unix_socket* socket = (unix_socket*)desc->inode;
    if (!socket->is_connected)
        return -EINVAL;

    ring_buf* buf = buf_to_read(desc);
    for (;;) {
        int rc = file_description_block(desc, is_readable, 0);
        if (IS_ERR(rc))
            return rc;

        mutex_lock(&socket->lock);
        if (!ring_buf_is_empty(buf)) {
            ssize_t nread = ring_buf_read(buf, buffer, count);
            mutex_unlock(&socket->lock);
            return nread;
        }
        mutex_unlock(&socket->lock);

        if (!is_open_for_reading(desc))
            return 0;
    }
}

static bool is_writable(file_description* desc) {
    unix_socket* socket = (unix_socket*)desc->inode;
    if (is_connector(desc)) {
        if (!socket->is_open_for_writing_to_acceptor)
            return false;
    } else if (!socket->is_open_for_writing_to_connector) {
        return true;
    }
    ring_buf* buf = buf_to_write(desc);
    return !ring_buf_is_full(buf);
}

static ssize_t unix_socket_write(file_description* desc, const void* buffer,
                                 size_t count) {
    unix_socket* socket = (unix_socket*)desc->inode;
    if (!socket->is_connected)
        return -ENOTCONN;

    ring_buf* buf = buf_to_write(desc);
    for (;;) {
        int rc = file_description_block(desc, is_writable, 0);
        if (IS_ERR(rc))
            return rc;

        if (!is_connector(desc) && !socket->is_open_for_writing_to_connector) {
            int rc = process_send_signal_to_one(current->pid, SIGPIPE);
            if (IS_ERR(rc))
                return rc;
            return -EPIPE;
        }

        mutex_lock(&socket->lock);
        if (!ring_buf_is_full(buf)) {
            ssize_t nwritten = ring_buf_write(buf, buffer, count);
            mutex_unlock(&socket->lock);
            return nwritten;
        }
        mutex_unlock(&socket->lock);
    }
}

static short unix_socket_poll(file_description* desc, short events) {
    unix_socket* socket = (unix_socket*)desc->inode;
    short revents = 0;
    if (events & POLLIN) {
        bool can_read =
            socket->is_connected ? is_readable(desc) : socket->num_pending > 0;
        if (can_read)
            revents |= POLLIN;
    }
    if (events & POLLOUT) {
        bool can_write = socket->is_connected && is_writable(desc);
        if (can_write)
            revents |= POLLOUT;
    }
    if (!socket->is_open_for_writing_to_connector &&
        !socket->is_open_for_writing_to_acceptor)
        revents |= POLLHUP;
    return revents;
}

unix_socket* unix_socket_create(void) {
    unix_socket* socket = kmalloc(sizeof(unix_socket));
    if (!socket)
        return ERR_PTR(-ENOMEM);
    *socket = (unix_socket){0};

    struct inode* inode = &socket->inode;
    static file_ops fops = {
        .destroy_inode = unix_socket_destroy_inode,
        .close = unix_socket_close,
        .read = unix_socket_read,
        .write = unix_socket_write,
        .poll = unix_socket_poll,
    };
    inode->fops = &fops;
    inode->mode = S_IFSOCK;
    inode->ref_count = 1;

    socket->state = SOCKET_STATE_OPENED;
    socket->is_open_for_writing_to_connector = true;
    socket->is_open_for_writing_to_acceptor = true;

    int rc = ring_buf_init(&socket->to_acceptor_buf, PAGE_SIZE);
    if (IS_ERR(rc)) {
        kfree(socket);
        return ERR_PTR(rc);
    }
    rc = ring_buf_init(&socket->to_connector_buf, PAGE_SIZE);
    if (IS_ERR(rc)) {
        ring_buf_destroy(&socket->to_acceptor_buf);
        kfree(socket);
        return ERR_PTR(rc);
    }

    return socket;
}

int unix_socket_bind(unix_socket* socket, struct inode* addr_inode) {
    mutex_lock(&socket->lock);
    if (socket->is_bound) {
        mutex_unlock(&socket->lock);
        return -EINVAL;
    }
    addr_inode->bound_socket = socket;
    socket->is_bound = true;
    mutex_unlock(&socket->lock);
    return 0;
}

int unix_socket_listen(unix_socket* socket, int backlog) {
    mutex_lock(&socket->lock);
    switch (socket->state) {
    case SOCKET_STATE_OPENED:
    case SOCKET_STATE_LISTENING:
        break;
    default:
        mutex_unlock(&socket->lock);
        return -EINVAL;
    }
    if (!socket->is_bound) {
        mutex_unlock(&socket->lock);
        return -EINVAL;
    }
    socket->backlog = backlog;
    if (socket->state == SOCKET_STATE_OPENED)
        socket->state = SOCKET_STATE_LISTENING;
    mutex_unlock(&socket->lock);
    return 0;
}

static bool is_acceptable(file_description* desc) {
    unix_socket* socket = (unix_socket*)desc->inode;
    return socket->num_pending > 0;
}

unix_socket* unix_socket_accept(file_description* desc) {
    if (!S_ISSOCK(desc->inode->mode))
        return ERR_PTR(-ENOTSOCK);

    unix_socket* listener = (unix_socket*)desc->inode;

    mutex_lock(&listener->lock);
    bool is_listening = listener->state == SOCKET_STATE_LISTENING;
    mutex_unlock(&listener->lock);
    if (!is_listening)
        return ERR_PTR(-EINVAL);

    for (;;) {
        int rc = file_description_block(desc, is_acceptable, 0);
        if (IS_ERR(rc))
            return ERR_PTR(rc);

        mutex_lock(&listener->lock);

        unix_socket* connector = listener->next;
        if (connector) {
            listener->next = connector->next;
            --listener->num_pending;
        }

        mutex_unlock(&listener->lock);

        if (!connector)
            continue;

        mutex_lock(&connector->lock);
        ASSERT(connector->state == SOCKET_STATE_PENDING);
        connector->state = SOCKET_STATE_CONNECTED;
        connector->is_connected = true;
        mutex_unlock(&connector->lock);
        return connector;
    }
}

static bool is_connectable(file_description* desc) {
    unix_socket* connector = (unix_socket*)desc->inode;
    return connector->is_connected;
}

int unix_socket_connect(file_description* desc, struct inode* addr_inode) {
    if (!S_ISSOCK(desc->inode->mode))
        return -ENOTSOCK;

    unix_socket* listener = addr_inode->bound_socket;
    if (!listener)
        return -ECONNREFUSED;

    unix_socket* connector = (unix_socket*)desc->inode;
    mutex_lock(&connector->lock);

    switch (connector->state) {
    case SOCKET_STATE_LISTENING:
        mutex_unlock(&connector->lock);
        return -EINVAL;
    case SOCKET_STATE_PENDING:
    case SOCKET_STATE_CONNECTED:
        mutex_unlock(&connector->lock);
        return -EISCONN;
    default:
        break;
    }

    mutex_lock(&listener->lock);

    if (listener->state != SOCKET_STATE_LISTENING ||
        listener->num_pending >= (size_t)listener->backlog) {
        mutex_unlock(&listener->lock);
        mutex_unlock(&connector->lock);
        return -ECONNREFUSED;
    }

    ++listener->num_pending;

    connector->connector_fd = desc;
    connector->state = SOCKET_STATE_PENDING;
    connector->next = NULL;

    inode_ref((struct inode*)connector);

    if (listener->next) {
        unix_socket* it = listener->next;
        while (it->next)
            it = it->next;
        it->next = connector;
    } else {
        listener->next = connector;
    }

    mutex_unlock(&listener->lock);
    mutex_unlock(&connector->lock);

    return file_description_block(desc, is_connectable, 0);
}

int unix_socket_shutdown(file_description* desc, int how) {
    if (!S_ISSOCK(desc->inode->mode))
        return -ENOTSOCK;

    switch (how) {
    case SHUT_RD:
    case SHUT_WR:
    case SHUT_RDWR:
        break;
    default:
        return -EINVAL;
    }

    bool shut_read = how == SHUT_RD || how == SHUT_RDWR;
    bool shut_write = how == SHUT_WR || how == SHUT_RDWR;
    bool conn = is_connector(desc);
    unix_socket* socket = (unix_socket*)desc->inode;
    if ((conn && shut_read) || (!conn && shut_write))
        socket->is_open_for_writing_to_connector = false;
    if ((conn && shut_write) || (!conn && shut_read))
        socket->is_open_for_writing_to_acceptor = false;

    return 0;
}
