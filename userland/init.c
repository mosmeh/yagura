#include "stdlib.h"
#include "syscall.h"

int main(void) {
    for (;;) {
        pid_t pid = fork();
        if (pid == 0) {
            char* argv[] = {NULL};
            char* envp[] = {"PATH=/initrd", NULL};
            if (execve("/initrd/sh", argv, envp) < 0) {
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
