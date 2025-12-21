#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/socket.h>
#include <kernel/api/sys/un.h>
#include <kernel/memory/safe_string.h>
#include <kernel/socket.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task.h>

int sys_socket(int domain, int type, int protocol) {
    (void)protocol;
    if (domain != AF_UNIX || type != SOCK_STREAM)
        return -EAFNOSUPPORT;

    struct inode* socket FREE(inode) = unix_socket_create();
    if (IS_ERR(ASSERT(socket)))
        return PTR_ERR(socket);
    struct file* file FREE(file) = inode_open(socket, O_RDWR);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return task_alloc_fd(-1, file);
}

int sys_bind(int sockfd, const struct sockaddr* user_addr, socklen_t addrlen) {
    struct file* file FREE(file) = task_ref_file(sockfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    if (!S_ISSOCK(file->inode->mode))
        return -ENOTSOCK;

    if (addrlen <= sizeof(sa_family_t) || sizeof(struct sockaddr_un) < addrlen)
        return -EINVAL;

    struct sockaddr_un addr_un;
    if (copy_from_user(&addr_un, user_addr, addrlen))
        return -EFAULT;

    if (addr_un.sun_family != AF_UNIX)
        return -EINVAL;

    char path[UNIX_PATH_MAX + 1];
    strncpy(path, addr_un.sun_path, sizeof(path));

    struct file* addr_file FREE(file) =
        vfs_open(path, O_CREAT | O_EXCL, S_IFSOCK);
    if (IS_ERR(ASSERT(addr_file))) {
        if (PTR_ERR(addr_file) == -EEXIST)
            return -EADDRINUSE;
        return PTR_ERR(addr_file);
    }

    return unix_socket_bind(file->inode, addr_file->inode);
}

int sys_listen(int sockfd, int backlog) {
    struct file* file FREE(file) = task_ref_file(sockfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    if (!S_ISSOCK(file->inode->mode))
        return -ENOTSOCK;
    return unix_socket_listen(file->inode, backlog);
}

int sys_accept4(int sockfd, struct sockaddr* user_addr, socklen_t* user_addrlen,
                int flags) {
    (void)flags;

    struct file* file FREE(file) = task_ref_file(sockfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    if (user_addr) {
        if (!user_addrlen)
            return -EINVAL;

        socklen_t requested_addrlen;
        if (copy_from_user(&requested_addrlen, user_addrlen, sizeof(socklen_t)))
            return -EFAULT;

        struct sockaddr_un addr_un = {.sun_family = AF_UNIX, .sun_path = {0}};
        if (copy_to_user(user_addr, &addr_un, requested_addrlen))
            return -EFAULT;

        socklen_t actual_addrlen = sizeof(struct sockaddr_un);
        if (copy_to_user(user_addrlen, &actual_addrlen, sizeof(socklen_t)))
            return -EFAULT;
    }

    struct inode* connector FREE(inode) = unix_socket_accept(file);
    if (PTR_ERR(connector) == -EINTR)
        return -ERESTARTSYS;
    if (IS_ERR(ASSERT(connector)))
        return PTR_ERR(connector);
    struct file* connector_file FREE(file) = inode_open(connector, O_RDWR);
    if (IS_ERR(ASSERT(connector_file)))
        return PTR_ERR(connector_file);

    return task_alloc_fd(-1, connector_file);
}

int sys_connect(int sockfd, const struct sockaddr* user_addr,
                socklen_t addrlen) {
    struct file* file FREE(file) = task_ref_file(sockfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    if (addrlen <= sizeof(sa_family_t) || sizeof(struct sockaddr_un) < addrlen)
        return -EINVAL;

    struct sockaddr_un addr_un;
    if (copy_from_user(&addr_un, user_addr, addrlen))
        return -EFAULT;

    if (addr_un.sun_family != AF_UNIX)
        return -EINVAL;

    char path[UNIX_PATH_MAX + 1];
    strncpy(path, addr_un.sun_path, sizeof(path));

    struct file* addr_file FREE(file) = vfs_open(path, 0, 0);
    if (IS_ERR(ASSERT(addr_file)))
        return PTR_ERR(addr_file);

    int rc = unix_socket_connect(file, addr_file->inode);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

int sys_shutdown(int sockfd, int how) {
    struct file* file FREE(file) = task_ref_file(sockfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return unix_socket_shutdown(file, how);
}
