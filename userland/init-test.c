#include <fcntl.h>
#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static int spawn(char* filename) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        abort();
    }
    if (pid == 0) {
        char* argv[] = {filename, NULL};
        static char* envp[] = {NULL};
        if (execve(argv[0], argv, envp) < 0) {
            perror("execve");
            abort();
        }
    }
    return waitpid(pid, NULL, 0);
}

int main(void) {
    ASSERT(getpid() == 1);

    ASSERT_OK(mount("tmpfs", "/dev", "tmpfs", 0, NULL));

    ASSERT_OK(mknod("/dev/console", S_IFCHR, makedev(5, 1)));
    int fd = open("/dev/console", O_RDWR);
    ASSERT(fd == STDIN_FILENO);
    ASSERT_OK(dup2(fd, STDOUT_FILENO));
    ASSERT_OK(dup2(fd, STDERR_FILENO));

    ASSERT_OK(mkdir("/dev/shm", 0));
    ASSERT_OK(mount("tmpfs", "/dev/shm", "tmpfs", 0, NULL));

    ASSERT_OK(spawn("/bin/usertests"));
    ASSERT_OK(spawn("/bin/xv6-usertests"));

    reboot(RB_POWEROFF);
    UNREACHABLE();
}
