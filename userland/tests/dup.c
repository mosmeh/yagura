#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    errno = 0;
    ASSERT_ERR(dup(-1));
    ASSERT(errno == EBADF);

    int fd1 = ASSERT_OK(dup(STDIN_FILENO));
    ASSERT(fd1 != STDIN_FILENO);

    errno = 0;
    ASSERT_ERR(dup2(-1, 100));
    ASSERT(errno == EBADF);

    int fd2 = dup2(STDIN_FILENO, 100);
    ASSERT(fd2 == 100);

    errno = 0;
    ASSERT_ERR(dup2(STDIN_FILENO, -1));
    ASSERT(errno == EBADF);

    errno = 0;
    ASSERT_ERR(dup3(-1, 101, 0));
    ASSERT(errno == EBADF);

    errno = 0;
    ASSERT_ERR(dup3(STDIN_FILENO, -1, 0));
    ASSERT(errno == EBADF);

    int fd3 = dup3(STDIN_FILENO, 101, O_CLOEXEC);
    ASSERT(fd3 == 101);
    ASSERT(fcntl(fd3, F_GETFD) & FD_CLOEXEC);

    int fd4 = ASSERT_OK(fcntl(fd2, F_DUPFD, 150));
    ASSERT(fd4 >= 150);

    int fd5 = ASSERT_OK(fcntl(fd2, F_DUPFD_CLOEXEC, 200));
    ASSERT(fd5 >= 200);
    ASSERT(fcntl(fd5, F_GETFD) & FD_CLOEXEC);

    int fd6 = dup2(fd3, 250);
    ASSERT(fd6 == 250);
    ASSERT(!(fcntl(fd6, F_GETFD) & FD_CLOEXEC));

    int fd7 = dup3(fd3, 251, 0);
    ASSERT(fd7 == 251);
    ASSERT(!(fcntl(fd7, F_GETFD) & FD_CLOEXEC));

    int fd8 = ASSERT_OK(fcntl(fd3, F_DUPFD, 252));
    ASSERT(!(fcntl(fd8, F_GETFD) & FD_CLOEXEC));

    return EXIT_SUCCESS;
}
