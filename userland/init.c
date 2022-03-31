#include "stdlib.h"
#include "syscall.h"
#include <common/panic.h>

void spawn_process(const char* filename) {
    if (fork() == 0) {
        char* argv[] = {NULL};
        char* envp[] = {NULL};
        ASSERT_OK(execve(filename, argv, envp));
    }
}

void _start(void) {
    spawn_process("/fs-test");
    spawn_process("/socket-test");
    exit(0);
}
