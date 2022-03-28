#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/socket.h>
#include <kernel/api/stat.h>
#include <kernel/fs/fs.h>
#include <kernel/kmalloc.h>
#include <kernel/panic.h>
#include <kernel/process.h>

typedef struct local_socket {
    fs_node inner;
    int backlog;
} local_socket;

uintptr_t sys_socket(int domain, int type, int protocol) {
    (void)protocol;
    if (domain != AF_UNIX || type != SOCK_STREAM)
        return -EAFNOSUPPORT;

    local_socket* socket = kmalloc(sizeof(local_socket));
    if (!socket)
        return -ENOMEM;
    memset(socket, 0, sizeof(local_socket));
    socket->inner.mode = S_IFSOCK;

    return process_alloc_file_descriptor(&socket->inner);
}

uintptr_t sys_bind(int sockfd, const sockaddr* addr, socklen_t addrlen) {
    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (!S_ISSOCK(desc->node->mode))
        return -ENOTSOCK;

    KASSERT(addrlen == sizeof(sockaddr_un));

    const sockaddr_un* addr_un = (const sockaddr_un*)addr;
    KASSERT(addr->sa_family == AF_UNIX);

    const char* path = kstrndup(addr_un->sun_path, sizeof(addr_un->sun_path));
    if (!path)
        return -ENOMEM;

    fs_node* node = vfs_open(path, O_RDWR | O_CREAT | O_EXCL, S_IFSOCK | 0777);
    if (IS_ERR(node)) {
        if (PTR_ERR(node) == -EEXIST)
            return -EADDRINUSE;
        return PTR_ERR(node);
    }
    node->ino = sockfd;
    return 0;
}

uintptr_t sys_listen(int sockfd, int backlog) {
    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (!S_ISSOCK(desc->node->mode))
        return -ENOTSOCK;

    local_socket* socket = (local_socket*)desc->node;
    socket->backlog = backlog;
    return 0;
}

uintptr_t sys_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    file_description* desc = process_get_file_description(sockfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (!S_ISSOCK(desc->node->mode))
        return -ENOTSOCK;
    (void)addr;
    (void)addrlen;
    KUNIMPLEMENTED();
}

uintptr_t sys_connect(int sockfd, const struct sockaddr* addr,
                      socklen_t addrlen) {
    (void)sockfd;
    (void)addr;
    (void)addrlen;
    KUNIMPLEMENTED();
}
