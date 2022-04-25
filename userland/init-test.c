#include "stdlib.h"
#include "syscall.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/reboot.h>
#include <kernel/api/unistd.h>

int main(void) {
    ASSERT(getpid() == 1);
    ASSERT(open("/dev/console", O_RDONLY) == STDIN_FILENO);
    ASSERT(open("/dev/console", O_WRONLY) == STDOUT_FILENO);
    ASSERT(open("/dev/console", O_WRONLY) == STDERR_FILENO);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        abort();
    }
    if (pid == 0) {
        static char* argv[] = {NULL};
        static char* envp[] = {NULL};
        if (execve("/bin/run-tests", argv, envp) < 0) {
            perror("execve");
            abort();
        }
    }
    if (waitpid(pid, NULL, 0) < 0) {
        perror("waitpid");
        abort();
    }

    reboot(RB_POWEROFF);
    UNREACHABLE();
}
