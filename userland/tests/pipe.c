#include "../io.h"
#include <common/macros.h>
#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/limits.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static _Noreturn void peer(int send_fd, int recv_fd) {
    static unsigned buf[1024];
    size_t total = 0;
    for (size_t i = 0; i < 10000; i += 1024) {
        size_t s = MIN(1024, 10000 - i) * sizeof(unsigned);
        ASSERT_OK(read_exact(recv_fd, buf, s));
        for (size_t j = 0; j < s / sizeof(unsigned); ++j)
            ASSERT(buf[j] == total / sizeof(unsigned) + j);
        total += s;
    }

    int flag = ASSERT_OK(fcntl(recv_fd, F_GETFL));
    ASSERT_OK(fcntl(recv_fd, F_SETFL, flag | O_NONBLOCK));

    char c;
    ASSERT_ERRNO(read(recv_fd, &c, 1), EAGAIN);

    ASSERT_OK(write_all(send_fd, "x", 1));

    ASSERT_OK(close(send_fd));
    ASSERT_OK(close(recv_fd));

    exit(0);
}

int main(void) {
    {
        int fds[2];
        ASSERT_OK(pipe(fds));
        ASSERT(fcntl(fds[0], F_SETPIPE_SZ, 8192) >= 8192);
        ASSERT(fcntl(fds[0], F_GETPIPE_SZ) >= 8192);

        unsigned char buf[8192];
        STATIC_ASSERT(sizeof(buf) > PIPE_BUF);
        for (size_t i = 0; i < sizeof(buf); ++i)
            buf[i] = i % ((size_t)UCHAR_MAX + 1);
        ASSERT_OK(write_all(fds[1], buf, sizeof(buf)));
        ASSERT_ERRNO(fcntl(fds[0], F_SETPIPE_SZ, 4096), EBUSY);

        for (size_t i = 0; i < 4096; ++i) {
            unsigned char c;
            ASSERT_OK(read_exact(fds[0], &c, 1));
            ASSERT(c == i % ((size_t)UCHAR_MAX + 1));
        }
        ASSERT(fcntl(fds[0], F_SETPIPE_SZ, 4096) >= 4096);

        for (size_t i = 4096; i < sizeof(buf); ++i) {
            unsigned char c;
            ASSERT_OK(read_exact(fds[0], &c, 1));
            ASSERT(c == i % ((size_t)UCHAR_MAX + 1));
        }

        ASSERT_OK(fcntl(fds[1], F_SETFL, O_NONBLOCK));

        size_t pipe_size = ASSERT_OK(fcntl(fds[0], F_GETPIPE_SZ));
        size_t nwritten = ASSERT_OK(write(fds[1], buf, sizeof(buf)));
        ASSERT(nwritten == MIN(pipe_size, PIPE_BUF));
        ASSERT_OK(read_exact(fds[0], buf, nwritten));

        STATIC_ASSERT(PIPE_BUF > 3000);
        ASSERT_OK(write_all(fds[1], buf, 3000));
        ASSERT_ERRNO(write(fds[1], buf, 2000), EAGAIN);
        ASSERT_ERRNO(write(fds[1], buf, PIPE_BUF), EAGAIN);
        nwritten = ASSERT_OK(write(fds[1], buf, PIPE_BUF + 1));
        ASSERT(nwritten > 0);
        ASSERT(nwritten <= PIPE_BUF - 3000);

        ASSERT_OK(close(fds[0]));
        ASSERT_OK(close(fds[1]));
    }

    ASSERT(poll(NULL, 0, 10) == 0);

    int recv_fds[2];
    ASSERT_OK(pipe(recv_fds));

    {
        struct pollfd pollfds[] = {
            {.fd = recv_fds[0], .events = POLLIN},
        };
        ASSERT(poll(pollfds, 1, 0) == 0);
        ASSERT(poll(pollfds, 1, 10) == 0);
    }

    int send_fds[2];
    ASSERT_OK(pipe(send_fds));
    ASSERT(fcntl(send_fds[1], F_SETPIPE_SZ, 4096) >= 4096);
    ASSERT(fcntl(send_fds[0], F_GETPIPE_SZ) >= 4096);

    pid_t pid = ASSERT_OK(fork());
    if (pid == 0)
        peer(recv_fds[1], send_fds[0]);

    static unsigned buf[10000];
    for (size_t i = 0; i < 10000; ++i)
        buf[i] = i;
    ASSERT_OK(write_all(send_fds[1], buf, sizeof(buf)));

    int dummy_fds[2];
    ASSERT_OK(pipe(dummy_fds));

    {
        struct pollfd pollfds[] = {
            {.fd = dummy_fds[0], .events = POLLIN},
            {.fd = recv_fds[0], .events = POLLIN},
        };
        ASSERT(poll(pollfds, 2, -1) == 1);
        ASSERT(pollfds[0].revents == 0);
        ASSERT(pollfds[1].revents == POLLIN);
    }

    int flag = ASSERT_OK(fcntl(send_fds[1], F_GETFL));
    ASSERT_OK(fcntl(send_fds[1], F_SETFL, flag | O_NONBLOCK));

    int nwritten;
    errno = 0;
    while ((nwritten = write(send_fds[1], buf, sizeof(buf))) > 0)
        ;
    ASSERT(nwritten < 0);
    ASSERT(errno == EAGAIN);

    {
        struct pollfd pollfds[] = {
            {.fd = send_fds[1], .events = POLLOUT},
            {.fd = dummy_fds[1], .events = POLLOUT},
        };
        ASSERT(poll(pollfds, 2, -1) == 1);
        ASSERT(pollfds[0].revents == 0);
        ASSERT(pollfds[1].revents == POLLOUT);
    }

    int status;
    ASSERT_OK(waitpid(pid, &status, 0));
    ASSERT(WIFEXITED(status));
    ASSERT(WEXITSTATUS(status) == 0);

    ASSERT_OK(close(send_fds[0]));
    ASSERT_OK(close(recv_fds[1]));
    ASSERT_OK(close(dummy_fds[0]));
    ASSERT_OK(close(dummy_fds[1]));

    {
        struct pollfd pollfds[] = {{.fd = send_fds[1]}, {.fd = recv_fds[0]}};
        ASSERT(poll(pollfds, 2, -1) == 2);
        ASSERT(pollfds[0].revents == POLLERR);
        ASSERT(pollfds[1].revents == POLLHUP);
    }

    ASSERT_OK(close(send_fds[1]));
    ASSERT_OK(close(recv_fds[0]));

    ASSERT_OK(mkfifo("/tmp/test-pipe", 0644));
    int fd = ASSERT_OK(open("/tmp/test-pipe", O_RDWR | O_NONBLOCK));
    ASSERT_OK(close(fd));

    return EXIT_SUCCESS;
}
