#include <common/macros.h>
#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/poll.h>
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

static _Noreturn void peer(int send_fd, int recv_fd) {
    static unsigned buf[1024];
    size_t total = 0;
    for (size_t i = 0; i < 10000; i += 1024) {
        size_t s = MIN(1024, 10000 - i) * sizeof(unsigned);
        ASSERT(read_all(recv_fd, buf, s) == s);
        for (size_t j = 0; j < s / sizeof(unsigned); ++j)
            ASSERT(buf[j] == total / sizeof(unsigned) + j);
        total += s;
    }

    int flag = fcntl(recv_fd, F_GETFL);
    ASSERT_OK(flag);
    ASSERT_OK(fcntl(recv_fd, F_SETFL, flag | O_NONBLOCK));

    char c;
    errno = 0;
    ASSERT_ERR(read(recv_fd, &c, 1));
    ASSERT(errno == EAGAIN);

    ASSERT(write_all(send_fd, "x", 1) == 1);

    ASSERT_OK(close(send_fd));
    ASSERT_OK(close(recv_fd));

    exit(0);
}

int main(void) {
    ASSERT(poll(NULL, 0, 10) == 0);

    int recv_fds[2];
    ASSERT_OK(pipe(recv_fds));

    struct pollfd pollfds1[] = {
        {.fd = recv_fds[0], .events = POLLIN},
    };
    ASSERT(poll(pollfds1, 1, 0) == 0);
    ASSERT(poll(pollfds1, 1, 10) == 0);

    int send_fds[2];
    ASSERT_OK(pipe(send_fds));

    pid_t pid = fork();
    ASSERT_OK(pid);
    if (pid == 0)
        peer(recv_fds[1], send_fds[0]);

    static unsigned buf[10000];
    for (size_t i = 0; i < 10000; ++i)
        buf[i] = i;
    ASSERT(write_all(send_fds[1], buf, sizeof(buf)) == sizeof(buf));

    int dummy_fds[2];
    ASSERT_OK(pipe(dummy_fds));

    struct pollfd pollfds2[] = {
        {.fd = dummy_fds[0], .events = POLLIN},
        {.fd = recv_fds[0], .events = POLLIN},
    };
    ASSERT(poll(pollfds2, 2, -1) == 1);
    ASSERT(pollfds2[0].revents == 0);
    ASSERT(pollfds2[1].revents == POLLIN);

    int flag = fcntl(send_fds[1], F_GETFL);
    ASSERT_OK(flag);
    ASSERT_OK(fcntl(send_fds[1], F_SETFL, flag | O_NONBLOCK));

    int nwritten;
    errno = 0;
    while ((nwritten = write(send_fds[1], buf, sizeof(buf))) > 0)
        ;
    ASSERT(nwritten < 0);
    ASSERT(errno == EAGAIN);

    struct pollfd pollfds3[] = {
        {.fd = send_fds[1], .events = POLLOUT},
        {.fd = dummy_fds[1], .events = POLLOUT},
    };
    ASSERT(poll(pollfds3, 2, -1) == 1);
    ASSERT(pollfds3[0].revents == 0);
    ASSERT(pollfds3[1].revents == POLLOUT);

    ASSERT_OK(waitpid(pid, NULL, 0));

    ASSERT_OK(close(send_fds[0]));
    ASSERT_OK(close(recv_fds[1]));
    ASSERT_OK(close(dummy_fds[0]));
    ASSERT_OK(close(dummy_fds[1]));

    struct pollfd pollfds4[] = {{.fd = send_fds[1]}, {.fd = recv_fds[0]}};
    ASSERT(poll(pollfds4, 2, -1) == 2);
    ASSERT(pollfds4[0].revents == POLLERR);
    ASSERT(pollfds4[1].revents == POLLHUP);

    ASSERT_OK(close(send_fds[1]));
    ASSERT_OK(close(recv_fds[0]));

    return EXIT_SUCCESS;
}
