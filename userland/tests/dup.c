#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    errno = 0;
    ASSERT_ERR(dup(-1));
    ASSERT(errno == EBADF);

    int fd1 = dup(STDIN_FILENO);
    ASSERT_OK(fd1);
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

    int fd3 = dup3(STDIN_FILENO, 101, 0);
    ASSERT(fd3 == 101);

    int fd4 = fcntl(fd2, F_DUPFD, 150);
    ASSERT_OK(fd4);
    ASSERT(fd4 >= 150);

    return EXIT_SUCCESS;
}
