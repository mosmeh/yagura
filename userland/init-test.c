#include "stdlib.h"
#include "syscall.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/reboot.h>

int main(void) {
    ASSERT(getpid() == 1);
    ASSERT(open("/dev/console", O_RDONLY) == 0);
    ASSERT(open("/dev/console", O_WRONLY) == 1);
    ASSERT(open("/dev/console", O_WRONLY) == 2);

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
