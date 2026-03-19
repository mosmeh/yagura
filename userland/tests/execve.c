#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void spawn(const char* pathname, char* const* argv, char* const* envp) {
    pid_t pid = ASSERT_OK(fork());
    if (pid == 0)
        ASSERT_OK(execve(pathname, argv, envp));
    int status;
    ASSERT_OK(waitpid(pid, &status, 0));
    ASSERT(WIFEXITED(status));
    ASSERT(WEXITSTATUS(status) == EXIT_SUCCESS);
}

static void signal_handler(int signum) { (void)signum; }

int main(int argc, char** argv) {
    ASSERT(argc > 0);

    if (argv[0][0] == 0)
        return EXIT_SUCCESS;

    if (argc > 1 && !strcmp(argv[1], "child")) {
        ASSERT_OK(close(100));
        ASSERT_OK(close(101));
        ASSERT_OK(close(102));

        ASSERT_ERRNO(close(103), EBADF);
        ASSERT_ERRNO(close(104), EBADF);
        ASSERT_ERRNO(close(105), EBADF);

        ASSERT(signal(SIGUSR1, signal_handler) == SIG_IGN);
        ASSERT(signal(SIGUSR2, signal_handler) == SIG_DFL);

        return EXIT_SUCCESS;
    }

    ASSERT_ERRNO(execve(NULL, NULL, NULL), EFAULT);

    spawn(argv[0], NULL, NULL);
    spawn(argv[0], (char*[]){NULL}, NULL);

    spawn("/bin/true", NULL, NULL);
    spawn("/bin/true", (char*[]){"true", NULL}, NULL);
    spawn("/bin/true", NULL, (char*[]){"KEY=VALUE", NULL});

    int fd = ASSERT_OK(open("/bin/true", O_RDONLY));
    ASSERT_OK(dup2(fd, 100));
    ASSERT_OK(dup2(fd, 101));
    ASSERT_OK(fcntl(fd, F_DUPFD, 102));
    ASSERT_OK(dup3(fd, 103, O_CLOEXEC));
    ASSERT_OK(fcntl(fd, F_DUPFD, 104));
    ASSERT_OK(fcntl(104, F_SETFD, FD_CLOEXEC));
    ASSERT_OK(fcntl(fd, F_DUPFD_CLOEXEC, 105));
    ASSERT_OK(close(fd));
    ASSERT(signal(SIGUSR1, SIG_IGN) == SIG_DFL);
    ASSERT(signal(SIGUSR2, signal_handler) == SIG_DFL);
    spawn(argv[0], (char*[]){argv[0], "child", NULL}, NULL);

    return EXIT_SUCCESS;
}
