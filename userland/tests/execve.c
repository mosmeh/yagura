#include <errno.h>
#include <panic.h>
#include <stdlib.h>
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

    errno = 0;
    ASSERT_ERR(execve(NULL, NULL, NULL));
    ASSERT(errno == EFAULT);

    spawn(argv[0], NULL, NULL);
    spawn(argv[0], (char*[]){NULL}, NULL);

    spawn("/bin/true", NULL, NULL);
    spawn("/bin/true", (char*[]){"true", NULL}, NULL);
    spawn("/bin/true", NULL, (char*[]){"KEY=VALUE", NULL});

    return EXIT_SUCCESS;
}
