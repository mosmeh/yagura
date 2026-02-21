#include "../io.h"
#include <errno.h>
#include <panic.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    {
        int pipe_fds[2];
        ASSERT_OK(pipe(pipe_fds));

        pid_t pid = ASSERT_OK(fork());
        if (pid == 0) {
            close(pipe_fds[1]);
            char buf;
            ASSERT_OK(read_exact(pipe_fds[0], &buf, 1));
            exit(42);
        }

        ASSERT(waitpid(pid, NULL, WNOHANG) == 0);

        close(pipe_fds[0]);
        ASSERT_OK(write_all(pipe_fds[1], "x", 1));
        int status;
        ASSERT(waitpid(pid, &status, 0) == pid);
        ASSERT(WIFEXITED(status));
        ASSERT(WEXITSTATUS(status) == 42);
    }

    ASSERT_ERRNO(waitpid(-1, NULL, WNOHANG), ECHILD);
    ASSERT_ERRNO(waitpid(-1, NULL, 0), ECHILD);

    {
        pid_t pid = ASSERT_OK(fork());
        if (pid == 0)
            exit(55);
        struct rusage rusage = {
            .ru_utime = {.tv_sec = -1, .tv_usec = -1},
            .ru_stime = {.tv_sec = -1, .tv_usec = -1},
        };
        int status;
        ASSERT(wait4(pid, &status, 0, &rusage) == pid);
        ASSERT(WIFEXITED(status));
        ASSERT(WEXITSTATUS(status) == 55);
        ASSERT(rusage.ru_utime.tv_sec >= 0);
        ASSERT(rusage.ru_utime.tv_usec >= 0);
        ASSERT(rusage.ru_stime.tv_sec >= 0);
        ASSERT(rusage.ru_stime.tv_usec >= 0);
    }
    {
        pid_t pid = ASSERT_OK(fork());
        if (pid == 0) {
            ASSERT_OK(raise(SIGSTOP));
            exit(66);
        }
        int status;
        ASSERT(waitpid(pid, &status, WUNTRACED) == pid);
        ASSERT(WIFSTOPPED(status));
        ASSERT(WSTOPSIG(status) == SIGSTOP);

        ASSERT(waitpid(-1, NULL, WUNTRACED | WNOHANG) == 0);

        ASSERT_OK(kill(pid, SIGCONT));
        ASSERT(waitpid(pid, &status, 0) == pid);
        ASSERT(WIFEXITED(status));
        ASSERT(WEXITSTATUS(status) == 66);
    }

    return EXIT_SUCCESS;
}
