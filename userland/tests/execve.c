#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void spawn(char* pathname, char** argv, char** envp) {
    pid_t pid = fork();
    ASSERT_OK(pid);
    if (pid == 0)
        ASSERT_OK(execve(pathname, argv, envp));
    int status;
    ASSERT_OK(waitpid(pid, &status, 0));
    ASSERT(WIFEXITED(status));
    ASSERT(WEXITSTATUS(status) == EXIT_SUCCESS);
}

int main(int argc, char** argv) {
    ASSERT(argc > 0);

    if (argv[0][0] == 0)
        return EXIT_SUCCESS;

    if (argc > 1 && !strcmp(argv[1], "child")) {
        ASSERT_OK(close(100));
        ASSERT_OK(close(101));
        ASSERT_OK(close(102));

        errno = 0;
        ASSERT_ERR(close(103));
        ASSERT(errno == EBADF);

        errno = 0;
        ASSERT_ERR(close(104));
        ASSERT(errno == EBADF);

        errno = 0;
        ASSERT_ERR(close(105));
        ASSERT(errno == EBADF);

        return EXIT_SUCCESS;
    }

    errno = 0;
    ASSERT_ERR(execve(NULL, NULL, NULL));
    ASSERT(errno == EFAULT);

    spawn(argv[0], NULL, NULL);
    spawn(argv[0], (char*[]){NULL}, NULL);

    spawn("/bin/true", NULL, NULL);
    spawn("/bin/true", (char*[]){"true", NULL}, NULL);
    spawn("/bin/true", NULL, (char*[]){"KEY=VALUE", NULL});

    int fd = open("/bin/true", O_RDONLY);
    ASSERT_OK(fd);
    ASSERT_OK(dup2(fd, 100));
    ASSERT_OK(dup2(fd, 101));
    ASSERT_OK(fcntl(fd, F_DUPFD, 102));
    ASSERT_OK(dup3(fd, 103, O_CLOEXEC));
    ASSERT_OK(fcntl(fd, F_DUPFD, 104));
    ASSERT_OK(fcntl(104, F_SETFD, FD_CLOEXEC));
    ASSERT_OK(fcntl(fd, F_DUPFD_CLOEXEC, 105));
    ASSERT_OK(close(fd));
    spawn(argv[0], (char*[]){argv[0], "child", NULL}, NULL);

    return EXIT_SUCCESS;
}
