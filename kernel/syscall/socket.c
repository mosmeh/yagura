#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/socket.h>
#include <kernel/api/stat.h>
#include <kernel/kmalloc.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/socket.h>

uintptr_t sys_socket(int domain, int type, int protocol) {
    (void)protocol;
    if (domain != AF_UNIX || type != SOCK_STREAM)
        return -EAFNOSUPPORT;

    unix_socket* socket = unix_socket_create();
    if (IS_ERR(socket))
        return PTR_ERR(socket);
    file_description* desc = fs_open((struct file*)socket, O_RDWR, 0);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return process_alloc_file_descriptor(desc);
}

uintptr_t sys_bind(int sockfd, const sockaddr* addr, socklen_t addrlen) {
    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (!S_ISSOCK(desc->file->mode))
        return -ENOTSOCK;
    unix_socket* socket = (unix_socket*)desc->file;

    if (addrlen != sizeof(sockaddr_un))
        return -EINVAL;
    const sockaddr_un* addr_un = (const sockaddr_un*)addr;
    if (addr->sa_family != AF_UNIX)
        return -EINVAL;

    const char* path = kstrndup(addr_un->sun_path, sizeof(addr_un->sun_path));
    if (!path)
        return -ENOMEM;

    file_description* bound_desc = vfs_open(path, O_CREAT | O_EXCL, S_IFSOCK);
    if (IS_ERR(bound_desc)) {
        if (PTR_ERR(bound_desc) == -EEXIST)
            return -EADDRINUSE;
        return PTR_ERR(bound_desc);
    }
    bound_desc->file->bound_socket = socket;
    return 0;
}

uintptr_t sys_listen(int sockfd, int backlog) {
    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (!S_ISSOCK(desc->file->mode))
        return -ENOTSOCK;

    unix_socket* socket = (unix_socket*)desc->file;
    unix_socket_set_backlog(socket, backlog);
    return 0;
}

// NOLINTNEXTLINE(readability-non-const-parameter)
uintptr_t sys_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    (void)addr;
    (void)addrlen;

    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (!S_ISSOCK(desc->file->mode))
        return -ENOTSOCK;

    unix_socket* listener = (unix_socket*)desc->file;
    unix_socket* connector = unix_socket_accept(listener);
    file_description* connector_desc =
        fs_open((struct file*)connector, O_RDWR, 0);
    if (IS_ERR(connector_desc))
        return PTR_ERR(connector_desc);
    return process_alloc_file_descriptor(connector_desc);
}

uintptr_t sys_connect(int sockfd, const struct sockaddr* addr,
                      socklen_t addrlen) {
    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (!S_ISSOCK(desc->file->mode))
        return -ENOTSOCK;

    if (addrlen != sizeof(sockaddr_un))
        return -EINVAL;
    const sockaddr_un* addr_un = (const sockaddr_un*)addr;
    if (addr->sa_family != AF_UNIX)
        return -EINVAL;
    const char* path = kstrndup(addr_un->sun_path, sizeof(addr_un->sun_path));
    if (!path)
        return -ENOMEM;
    file_description* listener_desc = vfs_open(path, 0, 0);
    if (IS_ERR(listener_desc))
        return PTR_ERR(listener_desc);
    unix_socket* listener = listener_desc->file->bound_socket;
    if (!listener)
        return -ECONNREFUSED;

    return unix_socket_connect(desc, listener);
}
