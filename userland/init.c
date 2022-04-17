#include "stdlib.h"
#include "syscall.h"
#include <kernel/api/fcntl.h>

pid_t spawn(const char* filename) {
    pid_t pid = fork();
    if (pid == 0) {
        static char* argv[] = {NULL};
        static char* envp[] = {"PATH=/bin", "HOME=/root", NULL};
        if (execve(filename, argv, envp) < 0) {
            perror("execve");
            abort();
        }
    }
    return pid;
}

int main(void) {
    ASSERT(open("/dev/console", O_RDONLY) == 0);
    ASSERT(open("/dev/console", O_WRONLY) == 1);
    ASSERT(open("/dev/console", O_WRONLY) == 2);

    chdir("/root");

    spawn("/bin/mouse_cursor");

    for (;;) {
        pid_t pid = spawn("/bin/sh");
        if (waitpid(pid, NULL, 0) < 0) {
            perror("waitpid");
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
