#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/linux/net.h>
#include <kernel/api/sys/socket.h>
#include <kernel/api/sys/un.h>
#include <kernel/fs/file.h>
#include <kernel/fs/path.h>
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

    mode_t mode = S_IFSOCK | (file->inode->mode & ~current->fs->umask);
    struct inode* addr_inode FREE(inode) = vfs_create(path, mode);
    if (IS_ERR(ASSERT(addr_inode))) {
        if (PTR_ERR(addr_inode) == -EEXIST)
            return -EADDRINUSE;
        return PTR_ERR(addr_inode);
    }

    return unix_socket_bind(file->inode, addr_inode);
}

long sys_listen(int sockfd, int backlog) {
    struct file* file FREE(file) = files_ref_file(current->files, sockfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    if (!S_ISSOCK(file->inode->mode))
        return -ENOTSOCK;
    return unix_socket_listen(file->inode, backlog);
}

long sys_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    return sys_accept4(sockfd, addr, addrlen, 0);
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

    char pathname[UNIX_PATH_MAX + 1];
    strlcpy(pathname, addr_un.sun_path, sizeof(pathname));

    struct path* path FREE(path) = vfs_resolve_path(pathname, 0);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);

    int rc = unix_socket_connect(file, path->inode);
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

long sys_socketcall(int call, unsigned long* user_args) {
    static const size_t num_args[] = {
        [SYS_SOCKET] = 3,  [SYS_BIND] = 3,   [SYS_CONNECT] = 3,
        [SYS_LISTEN] = 2,  [SYS_ACCEPT] = 3, [SYS_SHUTDOWN] = 2,
        [SYS_ACCEPT4] = 4,
    };
    if (call < 0 || ARRAY_SIZE(num_args) <= (size_t)call)
        return -EINVAL;

    size_t n = num_args[call];
    if (n == 0) // Unsupported call
        return -EINVAL;

    unsigned long a[6];
    ASSERT(n <= ARRAY_SIZE(a));
    if (copy_from_user(a, user_args, n * sizeof(unsigned long)))
        return -EFAULT;

    switch (call) {
    case SYS_SOCKET:
        return sys_socket(a[0], a[1], a[2]);
    case SYS_BIND:
        return sys_bind(a[0], (const void*)a[1], a[2]);
    case SYS_CONNECT:
        return sys_connect(a[0], (const void*)a[1], a[2]);
    case SYS_LISTEN:
        return sys_listen(a[0], a[1]);
    case SYS_ACCEPT:
        return sys_accept(a[0], (void*)a[1], (void*)a[2]);
    case SYS_SHUTDOWN:
        return sys_shutdown(a[0], a[1]);
    case SYS_ACCEPT4:
        return sys_accept4(a[0], (void*)a[1], (void*)a[2], a[3]);
    default:
        return -EINVAL;
    }
}
