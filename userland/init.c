#include <fcntl.h>
#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t spawn(char* filename) {
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (setpgid(0, 0) < 0) {
            perror("setpgid");
            abort();
        }

        char* argv[] = {filename, NULL};
        static char* envp[] = {"PATH=/bin", "HOME=/root", NULL};
        if (execve(filename, argv, envp) < 0) {
            perror("execve");
            abort();
        }
    }
    return pid;
}

int main(void) {
    ASSERT(getpid() == 1);

    ASSERT_OK(mknod("/dev/console", S_IFCHR, makedev(5, 1)));
    ASSERT(open("/dev/console", O_RDONLY) == STDIN_FILENO);
    ASSERT(open("/dev/console", O_WRONLY) == STDOUT_FILENO);
    ASSERT(open("/dev/console", O_WRONLY) == STDERR_FILENO);

    struct {
        const char* pathname;
        dev_t dev;
    } dev_files[] = {
        {"/dev/null", makedev(1, 3)},    {"/dev/zero", makedev(1, 5)},
        {"/dev/full", makedev(1, 7)},    {"/dev/random", makedev(1, 8)},
        {"/dev/urandom", makedev(1, 9)},
    };
    for (size_t i = 0; i < ARRAY_SIZE(dev_files); ++i) {
        if (mknod(dev_files[i].pathname, S_IFCHR, dev_files[i].dev) < 0)
            perror("mknod");
    }

    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0)
        perror("mount");

    if (mkdir("/dev/shm", 0) < 0)
        perror("mkdir");
    else if (mount("tmpfs", "/dev/shm", "tmpfs", 0, NULL) < 0)
        perror("mount");

    if (mount("procfs", "/proc", "procfs", 0, NULL) < 0)
        perror("mount");

    if (chdir("/root") < 0)
        perror("chdir");

    pid_t pid = spawn("/bin/moused");
    if (pid > 0) {
        waitpid(pid, NULL, 0);
        spawn("/bin/mouse-cursor");
    }

    for (;;) {
        pid = spawn("/bin/sh");
        if (pid < 0) {
            perror("spawn");
            continue;
        }
        while (waitpid(-1, NULL, 0) != pid)
            ;
    }

    UNREACHABLE();
}
