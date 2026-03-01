#include "../io.h"
#include <common/macros.h>
#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static struct sockaddr_un addr = {AF_UNIX, ""};

static _Noreturn void receiver(bool shut_rd) {
    int sockfd = ASSERT_OK(socket(AF_UNIX, SOCK_STREAM, 0));
    ASSERT_OK(connect(sockfd, (const struct sockaddr*)&addr,
                      sizeof(struct sockaddr_un)));

    ASSERT_ERRNO(connect(sockfd, (const struct sockaddr*)&addr,
                         sizeof(struct sockaddr_un)),
                 EISCONN);

    ASSERT_OK(shutdown(sockfd, SHUT_WR));

    static unsigned buf[1024];
    size_t total = 0;
    for (size_t i = 0; i < 55000; i += 1024) {
        size_t s = MIN(1024, 55000 - i) * sizeof(unsigned);
        ASSERT_OK(read_exact(sockfd, buf, s));
        for (size_t j = 0; j < s / sizeof(unsigned); ++j)
            ASSERT(buf[j] == total / sizeof(unsigned) + j);
        total += s;
    }

    if (shut_rd)
        ASSERT_OK(shutdown(sockfd, SHUT_RD));

    char c;
    ASSERT(read_to_end(sockfd, &c, 1) == 0);

    ASSERT_OK(close(sockfd));
    exit(0);
}

int main(void) {
    const char* prefix = "/tmp/test-socket";
    char path[UNIX_PATH_MAX + 1];
    memset(path, 'x', sizeof(path));
    memcpy(path, prefix, strlen(prefix));
    path[UNIX_PATH_MAX] = '\0';
    ASSERT(strlen(path) == UNIX_PATH_MAX);
    memcpy(addr.sun_path, path, UNIX_PATH_MAX);

    unlink(path);
    unlink("/tmp/test-socket2");
    unlink("/tmp/test-socket3");
    struct sockaddr_un addr2 = {AF_UNIX, "/tmp/test-socket2"};
    struct sockaddr_un addr3 = {AF_UNIX, "/tmp/test-socket3"};

    int sockfd = ASSERT_OK(socket(AF_UNIX, SOCK_STREAM, 0));

    int sockfd2 = ASSERT_OK(
        socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    ASSERT(fcntl(sockfd2, F_GETFL) & O_NONBLOCK);
    ASSERT(fcntl(sockfd2, F_GETFD) & FD_CLOEXEC);
    ASSERT_OK(bind(sockfd2, (const struct sockaddr*)&addr2,
                   sizeof(struct sockaddr_un)));
    ASSERT_OK(listen(sockfd2, 1));

    ASSERT_ERRNO(listen(sockfd, 1), EINVAL);
    ASSERT_ERRNO(accept(sockfd, NULL, NULL), EINVAL);

    ASSERT_OK(bind(sockfd, (const struct sockaddr*)&addr,
                   sizeof(struct sockaddr_un)));

    ASSERT_ERRNO(
        bind(sockfd, (const struct sockaddr*)&addr, sizeof(struct sockaddr_un)),
        EADDRINUSE);
    ASSERT_ERRNO(bind(sockfd, (const struct sockaddr*)&addr3,
                      sizeof(struct sockaddr_un)),
                 EINVAL);
    ASSERT_ERRNO(accept(sockfd, NULL, NULL), EINVAL);

    ASSERT_OK(listen(sockfd, 1));
    ASSERT_OK(listen(sockfd, 2));

    ASSERT_ERRNO(connect(sockfd, (const struct sockaddr*)&addr2,
                         sizeof(struct sockaddr_un)),
                 EINVAL);
    ASSERT_ERRNO(read(sockfd, "x", 1), EINVAL);

    char c = 'x';
    ASSERT_ERRNO(write(sockfd, &c, 1), ENOTCONN);

    pid_t pid1 = ASSERT_OK(fork());
    if (pid1 == 0)
        receiver(false);
    int peer_fd1 = ASSERT_OK(accept(sockfd, NULL, NULL));

    pid_t pid2 = ASSERT_OK(fork());
    if (pid2 == 0)
        receiver(true);
    int peer_fd2 = ASSERT_OK(accept(sockfd, NULL, NULL));

    ASSERT_OK(shutdown(peer_fd1, SHUT_RD));
    ASSERT(read_to_end(peer_fd1, &c, 1) == 0);

    static unsigned buf[10000];
    for (size_t j = 0; j < 10000; ++j)
        buf[j] = j;
    for (size_t i = 0; i < 55000; i += 10000) {
        size_t s = MIN(10000, 55000 - i) * sizeof(unsigned);
        ASSERT_OK(write_all(peer_fd1, buf, s));
        ASSERT_OK(write_all(peer_fd2, buf, s));
        for (size_t j = 0; j < 10000; ++j)
            buf[j] += 10000;
    }

    ASSERT_OK(shutdown(peer_fd1, SHUT_WR));

    int status;
    ASSERT_OK(waitpid(pid1, &status, 0));
    ASSERT(WIFEXITED(status));
    ASSERT(WEXITSTATUS(status) == 0);
    ASSERT_OK(waitpid(pid2, &status, 0));
    ASSERT(WIFEXITED(status));
    ASSERT(WEXITSTATUS(status) == 0);

    ASSERT_OK(close(sockfd));
    ASSERT_OK(close(sockfd2));
    ASSERT_OK(close(peer_fd1));
    ASSERT_OK(close(peer_fd2));

    return EXIT_SUCCESS;
}
