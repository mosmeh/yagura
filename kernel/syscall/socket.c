#include "syscall.h"
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/socket.h>
#include <kernel/api/sys/un.h>
#include <kernel/process.h>
#include <kernel/safe_string.h>
#include <kernel/socket.h>
#include <string.h>

int sys_socket(int domain, int type, int protocol) {
    (void)protocol;
    if (domain != AF_UNIX || type != SOCK_STREAM)
        return -EAFNOSUPPORT;

    unix_socket* socket = unix_socket_create();
    if (IS_ERR(socket))
        return PTR_ERR(socket);
    file_description* desc = inode_open((struct inode*)socket, O_RDWR, 0);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    int fd = process_alloc_file_descriptor(-1, desc);
    if (IS_ERR(fd))
        file_description_close(desc);
    return fd;
}

int sys_bind(int sockfd, const struct sockaddr* user_addr, socklen_t addrlen) {
    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (!S_ISSOCK(desc->inode->mode))
        return -ENOTSOCK;
    unix_socket* socket = (unix_socket*)desc->inode;

    if (addrlen <= sizeof(sa_family_t) || sizeof(struct sockaddr_un) < addrlen)
        return -EINVAL;

    struct sockaddr_un addr_un;
    if (!copy_from_user(&addr_un, user_addr, addrlen))
        return -EFAULT;

    if (addr_un.sun_family != AF_UNIX)
        return -EINVAL;

    char path[UNIX_PATH_MAX + 1];
    strncpy(path, addr_un.sun_path, sizeof(path));

    file_description* addr_desc = vfs_open(path, O_CREAT | O_EXCL, S_IFSOCK);
    if (IS_ERR(addr_desc)) {
        if (PTR_ERR(addr_desc) == -EEXIST)
            return -EADDRINUSE;
        return PTR_ERR(addr_desc);
    }

    int rc = unix_socket_bind(socket, addr_desc->inode);
    if (IS_ERR(rc)) {
        file_description_close(addr_desc);
        return rc;
    }

    return 0;
}

int sys_listen(int sockfd, int backlog) {
    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (!S_ISSOCK(desc->inode->mode))
        return -ENOTSOCK;

    unix_socket* socket = (unix_socket*)desc->inode;
    return unix_socket_listen(socket, backlog);
}

int sys_accept(int sockfd, struct sockaddr* user_addr,
               socklen_t* user_addrlen) {
    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);

    if (user_addr) {
        if (!user_addrlen)
            return -EINVAL;

        socklen_t requested_addrlen;
        if (!copy_from_user(&requested_addrlen, user_addrlen,
                            sizeof(socklen_t)))
            return -EFAULT;

        struct sockaddr_un addr_un = {.sun_family = AF_UNIX, .sun_path = {0}};
        if (!copy_to_user(user_addr, &addr_un, requested_addrlen))
            return -EFAULT;

        socklen_t actual_addrlen = sizeof(struct sockaddr_un);
        if (!copy_to_user(user_addrlen, &actual_addrlen, sizeof(socklen_t)))
            return -EFAULT;
    }

    unix_socket* connector = unix_socket_accept(desc);
    if (IS_ERR(connector))
        return PTR_ERR(connector);
    file_description* connector_desc =
        inode_open((struct inode*)connector, O_RDWR, 0);
    if (IS_ERR(connector_desc))
        return PTR_ERR(connector_desc);

    int fd = process_alloc_file_descriptor(-1, connector_desc);
    if (IS_ERR(fd)) {
        file_description_close(connector_desc);
        return fd;
    }

    return fd;
}

int sys_connect(int sockfd, const struct sockaddr* user_addr,
                socklen_t addrlen) {
    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);

    if (addrlen <= sizeof(sa_family_t) || sizeof(struct sockaddr_un) < addrlen)
        return -EINVAL;

    struct sockaddr_un addr_un;
    if (!copy_from_user(&addr_un, user_addr, addrlen))
        return -EFAULT;

    if (addr_un.sun_family != AF_UNIX)
        return -EINVAL;

    char path[UNIX_PATH_MAX + 1];
    strncpy(path, addr_un.sun_path, sizeof(path));

    file_description* addr_desc = vfs_open(path, 0, 0);
    if (IS_ERR(addr_desc))
        return PTR_ERR(addr_desc);

    return unix_socket_connect(desc, addr_desc->inode);
}

int sys_shutdown(int sockfd, int how) {
    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return unix_socket_shutdown(desc, how);
}
