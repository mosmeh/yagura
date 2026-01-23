#include <errno.h>
#include <panic.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int pipe_fds[2];
    ASSERT_OK(pipe(pipe_fds));

    pid_t pid = fork();
    ASSERT_OK(pid);
    if (pid == 0) {
        close(pipe_fds[1]);
        char buf;
        ASSERT(read(pipe_fds[0], &buf, 1) == 1);
        exit(42);
    }

    ASSERT(waitpid(pid, NULL, WNOHANG) == 0);

    close(pipe_fds[0]);
    ASSERT(write(pipe_fds[1], "x", 1) == 1);
    int status;
    ASSERT(waitpid(pid, &status, 0) == pid);
    ASSERT(WIFEXITED(status));
    ASSERT(WEXITSTATUS(status) == 42);

    errno = 0;
    ASSERT_ERR(waitpid(-1, NULL, WNOHANG));
    ASSERT(errno == ECHILD);

    errno = 0;
    ASSERT_ERR(waitpid(-1, NULL, 0));
    ASSERT(errno == ECHILD);

    return EXIT_SUCCESS;
}
