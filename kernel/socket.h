#pragma once

#include "fs/fs.h"
#include "ring_buf.h"

typedef struct unix_socket {
    struct inode inode;

    mutex lock;
    bool is_bound;
    enum {
        SOCKET_STATE_OPENED,
        SOCKET_STATE_LISTENING,
        SOCKET_STATE_PENDING,
        SOCKET_STATE_CONNECTED,
    } state;
    int backlog;

    atomic_size_t num_pending;
    struct unix_socket* next; // pending queue

    atomic_bool is_connected;
    struct file* connector_file;

    ring_buf to_connector_buf;
    ring_buf to_acceptor_buf;

    atomic_bool is_open_for_writing_to_connector;
    atomic_bool is_open_for_writing_to_acceptor;
} unix_socket;

unix_socket* unix_socket_create(void);
NODISCARD int unix_socket_bind(unix_socket*, struct inode* addr_inode);
NODISCARD int unix_socket_listen(unix_socket*, int backlog);
NODISCARD unix_socket* unix_socket_accept(struct file*);
NODISCARD int unix_socket_connect(struct file*, struct inode* addr_inode);
NODISCARD int unix_socket_shutdown(struct file*, int how);
