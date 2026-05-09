#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void) {
    int pipes[2];
    ASSERT_OK(pipe(pipes));

    int flags = ASSERT_OK(fcntl(pipes[0], F_GETFL));
    ASSERT(!(flags & O_NONBLOCK));

    int on = 1;
    ASSERT_OK(ioctl(pipes[0], FIONBIO, &on));
    flags = ASSERT_OK(fcntl(pipes[0], F_GETFL));
    ASSERT(flags & O_NONBLOCK);

    on = 0;
    ASSERT_OK(ioctl(pipes[0], FIONBIO, &on));
    flags = ASSERT_OK(fcntl(pipes[0], F_GETFL));
    ASSERT(!(flags & O_NONBLOCK));

    flags = ASSERT_OK(fcntl(pipes[1], F_GETFD));
    ASSERT(!(flags & FD_CLOEXEC));

    ASSERT_OK(ioctl(pipes[1], FIOCLEX));
    flags = ASSERT_OK(fcntl(pipes[1], F_GETFD));
    ASSERT(flags & FD_CLOEXEC);

    ASSERT_OK(ioctl(pipes[1], FIONCLEX));
    flags = ASSERT_OK(fcntl(pipes[1], F_GETFD));
    ASSERT(!(flags & FD_CLOEXEC));

    return EXIT_SUCCESS;
}
