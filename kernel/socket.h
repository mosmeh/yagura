#pragma once

#include <kernel/fs/fs.h>

void socket_init(void);

struct inode* unix_socket_create(void);
NODISCARD int unix_socket_bind(struct inode* socket, struct inode* addr_inode);
NODISCARD int unix_socket_listen(struct inode* socket, int backlog);
NODISCARD struct inode* unix_socket_accept(struct file*);
NODISCARD int unix_socket_connect(struct file*, struct inode* addr_inode);
NODISCARD int unix_socket_shutdown(struct file*, int how);
