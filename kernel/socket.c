#include <kernel/api/fcntl.h>
#include <kernel/api/signal.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/socket.h>
#include <kernel/containers/ring_buf.h>
#include <kernel/fs/file.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/vfs.h>
#include <kernel/panic.h>
#include <kernel/socket.h>
#include <kernel/task/signal.h>
#include <kernel/task/task.h>

struct unix_socket {
    struct inode vfs_inode;

    bool is_bound;
    enum {
        SOCKET_STATE_OPENED,
        SOCKET_STATE_LISTENING,
        SOCKET_STATE_PENDING,
        SOCKET_STATE_CONNECTED,
    } state;
    int backlog;

    _Atomic(size_t) num_pending;
    struct unix_socket* next; // pending queue

    _Atomic(bool) is_connected;
    _Atomic(struct file*) connector_file;

    struct ring_buf* ring_to_connector;
    struct ring_buf* ring_to_acceptor;

    _Atomic(bool) is_open_for_writing_to_connector;
    _Atomic(bool) is_open_for_writing_to_acceptor;

    struct waitqueue wait;
};

DEFINE_LOCKED(unix_socket, struct unix_socket, inode, vfs_inode)

static struct slab unix_socket_slab;
static struct mount* sock_mount;

void socket_init(void) {
    SLAB_INIT_FOR_TYPE(&unix_socket_slab, "unix_socket", struct unix_socket);

    static struct file_system sock_fs = {
        .name = "sockfs",
        .flags = FILE_SYSTEM_KERNEL_ONLY,
    };
    ASSERT_OK(file_system_register(&sock_fs));

    sock_mount = ASSERT_PTR(file_system_mount(&sock_fs, "sockfs"));
}

static bool is_unix_socket(const struct inode* inode) {
    return S_ISSOCK(inode->mode) && inode->mount == sock_mount;
}

static struct unix_socket* unix_socket_from_inode(struct inode* inode) {
    return CONTAINER_OF(inode, struct unix_socket, vfs_inode);
}

static struct unix_socket* unix_socket_from_file(struct file* file) {
    return unix_socket_from_inode(file->inode);
}

static void unix_socket_destroy(struct inode* inode) {
    struct unix_socket* socket = unix_socket_from_inode(inode);
    ring_buf_destroy(socket->ring_to_connector);
    ring_buf_destroy(socket->ring_to_acceptor);
    slab_free(&unix_socket_slab, socket);
}

static void unix_socket_close(struct file* file) {
    struct unix_socket* socket = unix_socket_from_file(file);
    socket->is_open_for_writing_to_connector = false;
    socket->is_open_for_writing_to_acceptor = false;
    waitqueue_wake_all(&socket->wait);
}

static bool is_connector(struct file* file) {
    return unix_socket_from_file(file)->connector_file == file;
}

static bool is_open_for_reading(struct file* file) {
    const struct unix_socket* socket = unix_socket_from_file(file);
    return is_connector(file) ? socket->is_open_for_writing_to_connector
                              : socket->is_open_for_writing_to_acceptor;
}

static struct ring_buf* ring_to_read(struct file* file) {
    const struct unix_socket* socket = unix_socket_from_file(file);
    return is_connector(file) ? socket->ring_to_connector
                              : socket->ring_to_acceptor;
}

static struct ring_buf* ring_to_write(struct file* file) {
    const struct unix_socket* socket = unix_socket_from_file(file);
    return is_connector(file) ? socket->ring_to_acceptor
                              : socket->ring_to_connector;
}

static bool is_readable(struct file* file) {
    if (!is_open_for_reading(file))
        return true;
    const struct ring_buf* ring = ring_to_read(file);
    return !ring_buf_is_empty(ring);
}

static ssize_t unix_socket_pread(struct file* file, void* user_buffer,
                                 size_t count, uint64_t offset) {
    (void)offset;

    struct unix_socket* socket = unix_socket_from_file(file);
    if (!socket->is_connected)
        return -EINVAL;

    struct ring_buf* ring = ring_to_read(file);
    for (;;) {
        if (!is_readable(file)) {
            if (file->flags & O_NONBLOCK)
                return -EAGAIN;
            if (WAIT_INTERRUPTIBLE(&socket->wait, is_readable(file)))
                return -EINTR;
        }

        {
            SCOPED_LOCK(unix_socket, socket);
            if (!ring_buf_is_empty(ring)) {
                ssize_t n = ring_buf_read_to_user(ring, user_buffer, count);
                if (n > 0)
                    waitqueue_wake_all(&socket->wait);
                return n;
            }
        }

        if (!is_open_for_reading(file))
            return 0;
    }
}

static bool is_writable(struct file* file) {
    struct unix_socket* socket = unix_socket_from_file(file);
    if (is_connector(file)) {
        if (!socket->is_open_for_writing_to_acceptor)
            return false;
    } else if (!socket->is_open_for_writing_to_connector) {
        return true;
    }
    const struct ring_buf* ring = ring_to_write(file);
    return !ring_buf_is_full(ring);
}

static ssize_t unix_socket_pwrite(struct file* file, const void* user_buffer,
                                  size_t count, uint64_t offset) {
    (void)offset;

    struct unix_socket* socket = unix_socket_from_file(file);
    if (!socket->is_connected)
        return -ENOTCONN;

    struct ring_buf* ring = ring_to_write(file);
    for (;;) {
        if (!is_writable(file)) {
            if (file->flags & O_NONBLOCK)
                return -EAGAIN;
            if (WAIT_INTERRUPTIBLE(&socket->wait, is_writable(file)))
                return -EINTR;
        }

        if (!is_connector(file) && !socket->is_open_for_writing_to_connector) {
            int rc = signal_send_to_tasks(0, current->tid, SIGPIPE);
            if (IS_ERR(rc))
                return rc;
            return -EPIPE;
        }

        SCOPED_LOCK(unix_socket, socket);
        if (!ring_buf_is_full(ring)) {
            ssize_t n = ring_buf_write_from_user(ring, user_buffer, count);
            if (n > 0)
                waitqueue_wake_all(&socket->wait);
            return n;
        }
    }
}

static short unix_socket_poll(struct file* file, short events) {
    struct unix_socket* socket = unix_socket_from_file(file);
    short revents = 0;
    if (events & POLLIN) {
        bool can_read =
            socket->is_connected ? is_readable(file) : socket->num_pending > 0;
        if (can_read)
            revents |= POLLIN;
    }
    if (events & POLLOUT) {
        bool can_write = socket->is_connected && is_writable(file);
        if (can_write)
            revents |= POLLOUT;
    }
    if ((events & POLLHUP) && !socket->is_open_for_writing_to_connector &&
        !socket->is_open_for_writing_to_acceptor)
        revents |= POLLHUP;
    return revents;
}

static _Atomic(ino_t) next_ino = 1;

struct inode* unix_socket_create(void) {
    struct unix_socket* socket = ASSERT(slab_alloc(&unix_socket_slab));
    if (IS_ERR(socket))
        return ERR_CAST(socket);
    *socket = (struct unix_socket){
        .vfs_inode = INODE_INIT,
    };

    struct inode* inode = &socket->vfs_inode;
    inode->ino = atomic_fetch_add(&next_ino, 1);
    static const struct inode_ops iops = {
        .destroy = unix_socket_destroy,
    };
    static const struct file_ops fops = {
        .close = unix_socket_close,
        .pread = unix_socket_pread,
        .pwrite = unix_socket_pwrite,
        .poll = unix_socket_poll,
    };
    inode->iops = &iops;
    inode->fops = &fops;
    inode->mode = S_IFSOCK | ACCESSPERMS;

    socket->state = SOCKET_STATE_OPENED;
    socket->is_open_for_writing_to_connector = true;
    socket->is_open_for_writing_to_acceptor = true;

    struct ring_buf* ring_to_acceptor FREE(ring_buf) =
        ASSERT(ring_buf_create(PAGE_SIZE));
    if (IS_ERR(ring_to_acceptor)) {
        slab_free(&unix_socket_slab, socket);
        return ERR_CAST(ring_to_acceptor);
    }

    struct ring_buf* ring_to_connector FREE(ring_buf) =
        ASSERT(ring_buf_create(PAGE_SIZE));
    if (IS_ERR(ring_to_connector)) {
        slab_free(&unix_socket_slab, socket);
        return ERR_CAST(ring_to_connector);
    }

    socket->ring_to_acceptor = TAKE_PTR(ring_to_acceptor);
    socket->ring_to_connector = TAKE_PTR(ring_to_connector);

    int rc = mount_commit_inode(sock_mount, inode);
    if (IS_ERR(rc)) {
        inode_unref(inode);
        return ERR_PTR(rc);
    }

    return inode;
}

int unix_socket_bind(struct inode* inode, struct inode* addr_inode) {
    if (!is_unix_socket(inode))
        return -ENOTSOCK;
    struct unix_socket* socket = unix_socket_from_inode(inode);
    SCOPED_LOCK(unix_socket, socket);
    if (socket->is_bound)
        return -EINVAL;
    addr_inode->bound_socket = inode;
    socket->is_bound = true;
    return 0;
}

int unix_socket_listen(struct inode* inode, int backlog) {
    if (!is_unix_socket(inode))
        return -ENOTSOCK;
    struct unix_socket* socket = unix_socket_from_inode(inode);
    SCOPED_LOCK(unix_socket, socket);
    switch (socket->state) {
    case SOCKET_STATE_OPENED:
    case SOCKET_STATE_LISTENING:
        break;
    default:
        return -EINVAL;
    }
    if (!socket->is_bound)
        return -EINVAL;
    socket->backlog = backlog;
    if (socket->state == SOCKET_STATE_OPENED)
        socket->state = SOCKET_STATE_LISTENING;
    return 0;
}

struct inode* unix_socket_accept(struct file* file) {
    if (!is_unix_socket(file->inode))
        return ERR_PTR(-ENOTSOCK);

    struct unix_socket* listener = unix_socket_from_file(file);

    {
        SCOPED_LOCK(unix_socket, listener);
        if (listener->state != SOCKET_STATE_LISTENING)
            return ERR_PTR(-EINVAL);
    }

    for (;;) {
        if (listener->num_pending == 0) {
            if (file->flags & O_NONBLOCK)
                return ERR_PTR(-EAGAIN);
            if (WAIT_INTERRUPTIBLE(&listener->wait, listener->num_pending > 0))
                return ERR_PTR(-EINTR);
        }

        struct unix_socket* connector;
        {
            SCOPED_LOCK(unix_socket, listener);
            connector = listener->next;
            if (connector) {
                listener->next = connector->next;
                --listener->num_pending;
            }
        }

        if (!connector)
            continue;

        SCOPED_LOCK(unix_socket, connector);
        ASSERT(connector->state == SOCKET_STATE_PENDING);
        connector->state = SOCKET_STATE_CONNECTED;
        connector->is_connected = true;

        waitqueue_wake_all(&connector->wait);

        return &connector->vfs_inode;
    }
}

int unix_socket_connect(struct file* file, struct inode* addr_inode) {
    if (!is_unix_socket(file->inode))
        return -ENOTSOCK;

    struct inode* bound_socket = addr_inode->bound_socket;
    if (!bound_socket)
        return -ECONNREFUSED;
    ASSERT(is_unix_socket(bound_socket));

    struct unix_socket* listener = unix_socket_from_inode(bound_socket);
    struct unix_socket* connector = unix_socket_from_file(file);

    {
        SCOPED_LOCK(unix_socket, connector);

        switch (connector->state) {
        case SOCKET_STATE_LISTENING:
            return -EINVAL;
        case SOCKET_STATE_PENDING:
        case SOCKET_STATE_CONNECTED:
            return -EISCONN;
        default:
            break;
        }

        SCOPED_LOCK(unix_socket, listener);

        if (listener->state != SOCKET_STATE_LISTENING ||
            listener->num_pending >= (size_t)listener->backlog)
            return -ECONNREFUSED;

        ++listener->num_pending;

        connector->connector_file = file;
        connector->state = SOCKET_STATE_PENDING;
        connector->next = NULL;

        inode_ref(&connector->vfs_inode);

        if (listener->next) {
            struct unix_socket* it = listener->next;
            while (it->next)
                it = it->next;
            it->next = connector;
        } else {
            listener->next = connector;
        }
    }

    waitqueue_wake_all(&listener->wait);

    if (!connector->is_connected) {
        if (file->flags & O_NONBLOCK)
            return -EAGAIN;
        if (WAIT_INTERRUPTIBLE(&connector->wait, connector->is_connected))
            return -EINTR;
    }

    return 0;
}

int unix_socket_shutdown(struct file* file, int how) {
    if (!is_unix_socket(file->inode))
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

    bool conn = is_connector(file);
    struct unix_socket* socket = unix_socket_from_file(file);

    bool closed = false;
    if ((conn && shut_read) || (!conn && shut_write)) {
        socket->is_open_for_writing_to_connector = false;
        closed = true;
    }
    if ((conn && shut_write) || (!conn && shut_read)) {
        socket->is_open_for_writing_to_acceptor = false;
        closed = true;
    }
    if (closed)
        waitqueue_wake_all(&socket->wait);

    return 0;
}
