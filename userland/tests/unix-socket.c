#include <common/macros.h>
#include <common/stdbool.h>
#include <common/string.h>
#include <errno.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static size_t read_all(int fd, void* buf, size_t count) {
    unsigned char* p = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t n = read(fd, p + total, count - total);
        ASSERT_OK(n);
        total += n;
    }
    return total;
}

static size_t write_all(int fd, const void* buf, size_t count) {
    const unsigned char* p = buf;
    size_t total = 0;
    while (total < count) {
        ssize_t nwritten = write(fd, p + total, count - total);
        ASSERT_OK(nwritten);
        total += nwritten;
    }
    return total;
}

static struct sockaddr_un addr = {AF_UNIX, ""};

static _Noreturn void receiver(bool shut_rd) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_OK(sockfd);
    ASSERT_OK(connect(sockfd, (const struct sockaddr*)&addr,
                      sizeof(struct sockaddr_un)));

    errno = 0;
    ASSERT_ERR(connect(sockfd, (const struct sockaddr*)&addr,
                       sizeof(struct sockaddr_un)));
    ASSERT(errno == EISCONN);

    ASSERT_OK(shutdown(sockfd, SHUT_WR));

    static unsigned buf[1024];
    size_t total = 0;
    for (size_t i = 0; i < 55000; i += 1024) {
        size_t s = MIN(1024, 55000 - i) * sizeof(unsigned);
        ASSERT(read_all(sockfd, buf, s) == s);
        for (size_t j = 0; j < s / sizeof(unsigned); ++j)
            ASSERT(buf[j] == total / sizeof(unsigned) + j);
        total += s;
    }

    if (shut_rd)
        ASSERT_OK(shutdown(sockfd, SHUT_RD));

    char c;
    ASSERT(read(sockfd, &c, 1) == 0);

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

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_OK(sockfd);

    int sockfd2 = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_OK(sockfd2);
    ASSERT_OK(bind(sockfd2, (const struct sockaddr*)&addr2,
                   sizeof(struct sockaddr_un)));
    ASSERT_OK(listen(sockfd2, 1));

    errno = 0;
    ASSERT_ERR(listen(sockfd, 1));
    ASSERT(errno == EINVAL);

    errno = 0;
    ASSERT_ERR(accept(sockfd, NULL, NULL));
    ASSERT(errno == EINVAL);

    ASSERT_OK(bind(sockfd, (const struct sockaddr*)&addr,
                   sizeof(struct sockaddr_un)));

    errno = 0;
    ASSERT_ERR(bind(sockfd, (const struct sockaddr*)&addr,
                    sizeof(struct sockaddr_un)));
    ASSERT(errno == EADDRINUSE);

    errno = 0;
    ASSERT_ERR(bind(sockfd, (const struct sockaddr*)&addr3,
                    sizeof(struct sockaddr_un)));
    ASSERT(errno == EINVAL);

    errno = 0;
    ASSERT_ERR(accept(sockfd, NULL, NULL));
    ASSERT(errno == EINVAL);

    ASSERT_OK(listen(sockfd, 1));
    ASSERT_OK(listen(sockfd, 2));

    errno = 0;
    ASSERT_ERR(connect(sockfd, (const struct sockaddr*)&addr2,
                       sizeof(struct sockaddr_un)));
    ASSERT(errno == EINVAL);

    errno = 0;
    ASSERT_ERR(read(sockfd, "x", 1));
    ASSERT(errno == EINVAL);

    char c = 'x';
    errno = 0;
    ASSERT_ERR(write(sockfd, &c, 1));
    ASSERT(errno == ENOTCONN);

    pid_t pid1 = fork();
    ASSERT_OK(pid1);
    if (pid1 == 0)
        receiver(false);
    int peer_fd1 = accept(sockfd, NULL, NULL);
    ASSERT_OK(peer_fd1);

    pid_t pid2 = fork();
    ASSERT_OK(pid2);
    if (pid2 == 0)
        receiver(true);
    int peer_fd2 = accept(sockfd, NULL, NULL);
    ASSERT_OK(peer_fd2);

    ASSERT_OK(shutdown(peer_fd1, SHUT_RD));
    ASSERT(read(peer_fd1, &c, 1) == 0);

    static unsigned buf[10000];
    for (size_t j = 0; j < 10000; ++j)
        buf[j] = j;
    for (size_t i = 0; i < 55000; i += 10000) {
        size_t s = MIN(10000, 55000 - i) * sizeof(unsigned);
        ASSERT(write_all(peer_fd1, buf, s) == s);
        ASSERT(write_all(peer_fd2, buf, s) == s);
        for (size_t j = 0; j < 10000; ++j)
            buf[j] += 10000;
    }

    ASSERT_OK(shutdown(peer_fd1, SHUT_WR));

    ASSERT_OK(waitpid(pid1, NULL, 0));
    ASSERT_OK(waitpid(pid2, NULL, 0));

    ASSERT_OK(close(sockfd));
    ASSERT_OK(close(sockfd2));
    ASSERT_OK(close(peer_fd1));
    ASSERT_OK(close(peer_fd2));

    return EXIT_SUCCESS;
}
