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

    return process_alloc_file_descriptor((struct file*)socket);
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

    struct file* file =
        vfs_open(path, O_RDWR | O_CREAT | O_EXCL, S_IFSOCK | 0777);
    if (IS_ERR(file)) {
        if (PTR_ERR(file) == -EEXIST)
            return -EADDRINUSE;
        return PTR_ERR(file);
    }
    file->bound_socket = socket;
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

uintptr_t sys_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    (void)addr;
    (void)addrlen;

    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (!S_ISSOCK(desc->file->mode))
        return -ENOTSOCK;

    unix_socket* listening = (unix_socket*)desc->file;
    unix_socket* connected = unix_socket_accept(listening);
    return process_alloc_file_descriptor((struct file*)connected);
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
    struct file* file = vfs_open(path, O_RDWR, 0);
    if (IS_ERR(file))
        return PTR_ERR(file);
    unix_socket* listening = file->bound_socket;
    if (!listening)
        return -ECONNREFUSED;

    return unix_socket_connect(desc, listening);
}
