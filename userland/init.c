#include "stdlib.h"
#include "syscall.h"

void spawn_process(const char* filename) {
    if (fork() == 0) {
        char* argv[] = {NULL};
        char* envp[] = {NULL};
        if (execve(filename, argv, envp) < 0)
            perror("execve");
    }
}

void _start(void) {
    spawn_process("/fs-test");
    spawn_process("/socket-test");
    exit(0);
}
