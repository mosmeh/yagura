#include "socket.h"
#include <private.h>

int socket(int domain, int type, int protocol) {
    RETURN_WITH_ERRNO(int, SYSCALL3(socket, domain, type, protocol));
}

int bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    RETURN_WITH_ERRNO(int, SYSCALL3(bind, sockfd, addr, addrlen));
}

int listen(int sockfd, int backlog) {
    RETURN_WITH_ERRNO(int, SYSCALL2(listen, sockfd, backlog));
}

int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    return accept4(sockfd, addr, addrlen, 0);
}

int accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) {
    RETURN_WITH_ERRNO(int, SYSCALL4(accept4, sockfd, addr, addrlen, flags));
}

int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    RETURN_WITH_ERRNO(int, SYSCALL3(connect, sockfd, addr, addrlen));
}

int shutdown(int sockfd, int how) {
    RETURN_WITH_ERRNO(int, SYSCALL2(shutdown, sockfd, how));
}
