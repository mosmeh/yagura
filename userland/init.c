#include "stdlib.h"
#include "syscall.h"
#include <kernel/api/fcntl.h>

int main(void) {
    ASSERT(open("/dev/ttyS0", O_RDONLY) == 0);
    ASSERT(open("/dev/ttyS0", O_WRONLY) == 1);
    ASSERT(open("/dev/ttyS0", O_WRONLY) == 2);

    chdir("/root");

    for (;;) {
        pid_t pid = fork();
        if (pid == 0) {
            static char* argv[] = {NULL};
            static char* envp[] = {"PATH=/bin", "HOME=/root", NULL};
            if (execve("/bin/sh", argv, envp) < 0) {
                perror("execve");
                abort();
            }
        }
        if (waitpid(pid, NULL, 0) < 0) {
            perror("waitpid");
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
