#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/socket.h>
#include <kernel/api/sys/un.h>
#include <kernel/fs/file.h>
#include <kernel/memory/safe_string.h>
#include <kernel/socket.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

#define SOCK_TYPE_MASK 0xf

long sys_socket(int domain, int type, int protocol) {
    if (domain != AF_UNIX)
        return -EAFNOSUPPORT;
    if (protocol && protocol != PF_UNIX)
        return -EPROTONOSUPPORT;
    if ((type & SOCK_TYPE_MASK) != SOCK_STREAM)
        return -ESOCKTNOSUPPORT;

    struct inode* socket FREE(inode) = unix_socket_create();
    if (IS_ERR(ASSERT(socket)))
        return PTR_ERR(socket);

    int file_flags = O_RDWR;
    if (type & SOCK_NONBLOCK)
        file_flags |= O_NONBLOCK;
    struct file* file FREE(file) = inode_open(socket, file_flags);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    int fd_flags = 0;
    if (type & SOCK_CLOEXEC)
        fd_flags |= FD_CLOEXEC;
    return files_alloc_fd(current->files, 0, file, fd_flags);
}

long sys_bind(int sockfd, const struct sockaddr* user_addr, socklen_t addrlen) {
    struct file* file FREE(file) = files_ref_file(current->files, sockfd);
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
    strlcpy(path, addr_un.sun_path, sizeof(path));

    struct file* addr_file FREE(file) =
        vfs_open(path, O_CREAT | O_EXCL, S_IFSOCK);
    if (IS_ERR(ASSERT(addr_file))) {
        if (PTR_ERR(addr_file) == -EEXIST)
            return -EADDRINUSE;
        return PTR_ERR(addr_file);
    }

    return unix_socket_bind(file->inode, addr_file->inode);
}

long sys_listen(int sockfd, int backlog) {
    struct file* file FREE(file) = files_ref_file(current->files, sockfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    if (!S_ISSOCK(file->inode->mode))
        return -ENOTSOCK;
    return unix_socket_listen(file->inode, backlog);
}

long sys_accept4(int sockfd, struct sockaddr* user_addr,
                 socklen_t* user_addrlen, int flags) {
    if (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC))
        return -EINVAL;

    struct file* file FREE(file) = files_ref_file(current->files, sockfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    if (user_addr) {
        socklen_t requested_addrlen;
        if (copy_from_user(&requested_addrlen, user_addrlen, sizeof(socklen_t)))
            return -EFAULT;

        sa_family_t family = AF_UNIX;
        if (copy_to_user(user_addr, &family,
                         MIN(requested_addrlen, sizeof(sa_family_t))))
            return -EFAULT;

        socklen_t actual_addrlen = sizeof(sa_family_t);
        if (copy_to_user(user_addrlen, &actual_addrlen, sizeof(socklen_t)))
            return -EFAULT;
    } else if (user_addrlen) {
        socklen_t zero = 0;
        if (copy_to_user(user_addrlen, &zero, sizeof(socklen_t)))
            return -EFAULT;
    }

    struct inode* connector FREE(inode) = unix_socket_accept(file);
    if (PTR_ERR(connector) == -EINTR)
        return -ERESTARTSYS;
    if (IS_ERR(ASSERT(connector)))
        return PTR_ERR(connector);

    int file_flags = O_RDWR;
    if (flags & SOCK_NONBLOCK)
        file_flags |= O_NONBLOCK;
    struct file* connector_file FREE(file) = inode_open(connector, file_flags);
    if (IS_ERR(ASSERT(connector_file)))
        return PTR_ERR(connector_file);

    int fd_flags = 0;
    if (flags & SOCK_CLOEXEC)
        fd_flags |= FD_CLOEXEC;
    return files_alloc_fd(current->files, 0, connector_file, fd_flags);
}

long sys_connect(int sockfd, const struct sockaddr* user_addr,
                 socklen_t addrlen) {
    struct file* file FREE(file) = files_ref_file(current->files, sockfd);
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
    strlcpy(path, addr_un.sun_path, sizeof(path));

    struct file* addr_file FREE(file) = vfs_open(path, 0, 0);
    if (IS_ERR(ASSERT(addr_file)))
        return PTR_ERR(addr_file);

    int rc = unix_socket_connect(file, addr_file->inode);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

long sys_shutdown(int sockfd, int how) {
    struct file* file FREE(file) = files_ref_file(current->files, sockfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return unix_socket_shutdown(file, how);
}
