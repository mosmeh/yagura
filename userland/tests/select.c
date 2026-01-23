#include <common/macros.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>

int main(void) {
    int pipes[2];
    ASSERT_OK(pipe(pipes));

    int fd = open("/tmp/test-select", O_CREAT | O_RDONLY, 0644);
    ASSERT_OK(fd);

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(pipes[0], &read_fds);
    FD_SET(fd, &read_fds);

    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(pipes[1], &write_fds);
    FD_SET(fd, &write_fds);

    int max_fd = MAX(pipes[0], pipes[1]);
    max_fd = MAX(max_fd, fd);

    int result = select(max_fd + 1, &read_fds, &write_fds, NULL, NULL);
    ASSERT(result == 3);
    ASSERT(!FD_ISSET(pipes[0], &read_fds));
    ASSERT(FD_ISSET(fd, &read_fds));
    ASSERT(FD_ISSET(pipes[1], &write_fds));
    ASSERT(FD_ISSET(fd, &write_fds));

    struct timeval tv_timeout = {.tv_sec = 0, .tv_usec = 1000};
    ASSERT(select(0, NULL, NULL, NULL, &tv_timeout) == 0);

    struct timespec ts_timeout = {.tv_sec = 0, .tv_nsec = 1000000};
    ASSERT(pselect(0, NULL, NULL, NULL, &ts_timeout, NULL) == 0);

    return EXIT_SUCCESS;
}
