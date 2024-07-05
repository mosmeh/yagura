#include <errno.h>
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
    if (pid < 0) {
        perror("fork");
        return -1;
    }
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

struct device_file {
    const char* pathname;
    mode_t mode;
    dev_t dev;
};

static void try_mknod(const struct device_file* file) {
    if (mknod(file->pathname, file->mode, file->dev) < 0) {
        perror("mknod");
        return;
    }

    int rc = open(file->pathname, 0);
    if (rc >= 0)
        return;
    if (errno != ENODEV) {
        perror("open");
        return;
    }
    if (unlink(file->pathname) < 0)
        perror("unlink");
}

int main(void) {
    ASSERT(getpid() == 1);

    ASSERT_OK(mount("tmpfs", "/dev", "tmpfs", 0, NULL));

    ASSERT_OK(mknod("/dev/console", S_IFCHR, makedev(5, 1)));
    int fd = open("/dev/console", O_RDWR);
    ASSERT(fd == STDIN_FILENO);
    ASSERT_OK(dup2(fd, STDOUT_FILENO));
    ASSERT_OK(dup2(fd, STDERR_FILENO));

    const struct device_file device_files[] = {
        {"/dev/null", S_IFCHR, makedev(1, 3)},
        {"/dev/zero", S_IFCHR, makedev(1, 5)},
        {"/dev/full", S_IFCHR, makedev(1, 7)},
        {"/dev/random", S_IFCHR, makedev(1, 8)},
        {"/dev/urandom", S_IFCHR, makedev(1, 9)},
        {"/dev/ttyS0", S_IFCHR, makedev(4, 64)},
        {"/dev/ttyS1", S_IFCHR, makedev(4, 65)},
        {"/dev/ttyS2", S_IFCHR, makedev(4, 66)},
        {"/dev/ttyS3", S_IFCHR, makedev(4, 67)},
        {"/dev/tty", S_IFCHR, makedev(5, 0)},
        {"/dev/psaux", S_IFCHR, makedev(10, 1)},
        {"/dev/kbd", S_IFCHR, makedev(11, 0)},
        {"/dev/dsp", S_IFCHR, makedev(14, 3)},
        {"/dev/fb0", S_IFBLK, makedev(29, 0)},
    };
    for (size_t i = 0; i < ARRAY_SIZE(device_files); ++i)
        try_mknod(&device_files[i]);

    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0)
        perror("mount");

    if (mkdir("/dev/shm", 0) < 0)
        perror("mkdir");
    else if (mount("tmpfs", "/dev/shm", "tmpfs", 0, NULL) < 0)
        perror("mount");

    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
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
        if (pid < 0)
            continue;
        while (waitpid(-1, NULL, 0) != pid)
            ;
    }

    UNREACHABLE();
}
