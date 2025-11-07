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

static pid_t do_spawn(const char* filename, char* const argv[]) {
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

        static char* envp[] = {"PATH=/bin", "HOME=/root", NULL};
        if (execve(filename, argv, envp) < 0) {
            perror("execve");
            abort();
        }
    }
    return pid;
}

static pid_t spawn(char* filename) {
    return do_spawn(filename, (char*[]){filename, NULL});
}

static pid_t spawn_getty(char* tty) {
    static char* filename = "/bin/getty";
    return do_spawn(filename, (char*[]){filename, tty, NULL});
}

struct device_file {
    char* pathname;
    mode_t mode;
    dev_t dev;
};

static bool try_mknod(const struct device_file* file) {
    if (mknod(file->pathname, file->mode, file->dev) < 0) {
        perror("mknod");
        return false;
    }

    int fd = open(file->pathname, 0);
    if (fd >= 0) {
        close(fd);
        return true;
    }
    if (errno != ENODEV) {
        perror("open");
        return false;
    }
    if (unlink(file->pathname) < 0)
        perror("unlink");
    return false;
}

int main(void) {
    ASSERT(getpid() == 1);

    ASSERT_OK(mount("tmpfs", "/dev", "tmpfs", 0, NULL));

    ASSERT_OK(mknod("/dev/console", S_IFCHR, makedev(5, 1)));
    int fd = open("/dev/console", O_RDWR);
    ASSERT(fd == STDIN_FILENO);
    ASSERT_OK(dup2(fd, STDOUT_FILENO));
    ASSERT_OK(dup2(fd, STDERR_FILENO));

    if (chdir("/root") < 0)
        perror("chdir");

    static const struct device_file device_files[] = {
        {"/dev/null", S_IFCHR, makedev(1, 3)},
        {"/dev/zero", S_IFCHR, makedev(1, 5)},
        {"/dev/full", S_IFCHR, makedev(1, 7)},
        {"/dev/random", S_IFCHR, makedev(1, 8)},
        {"/dev/urandom", S_IFCHR, makedev(1, 9)},
        {"/dev/kmsg", S_IFCHR, makedev(1, 11)},
        {"/dev/psaux", S_IFCHR, makedev(10, 1)},
        {"/dev/kbd", S_IFCHR, makedev(11, 0)},
        {"/dev/dsp", S_IFCHR, makedev(14, 3)},
        {"/dev/fb0", S_IFBLK, makedev(29, 0)},
    };
    for (size_t i = 0; i < ARRAY_SIZE(device_files); ++i)
        try_mknod(&device_files[i]);

    for (size_t i = 0; i < 64; ++i) {
        char pathname[16];
        (void)sprintf(pathname, "/dev/tty%u", i);
        struct device_file file = {
            .pathname = pathname,
            .mode = S_IFCHR,
            .dev = makedev(4, i),
        };
        if (try_mknod(&file))
            spawn_getty(pathname);
    }

    for (size_t i = 0; i < 4; ++i) {
        char pathname[16] = "/dev/ttyS";
        pathname[9] = '0' + i;
        struct device_file file = {
            .pathname = pathname,
            .mode = S_IFCHR,
            .dev = makedev(4, 64 + i),
        };
        if (try_mknod(&file))
            spawn_getty(pathname);
    }

    for (size_t i = 0; i < 256; ++i) {
        char pathname[16] = "/dev/vd";
        if (i < 26) {
            pathname[7] = 'a' + i;
        } else {
            pathname[7] = 'a' + i / 26 - 1;
            pathname[8] = 'a' + i % 26;
        }
        struct device_file file = {
            .pathname = pathname,
            .mode = S_IFBLK,
            .dev = makedev(254, i),
        };
        try_mknod(&file);
    }

    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0)
        perror("mount");

    if (mkdir("/dev/shm", 0) < 0)
        perror("mkdir");
    else if (mount("tmpfs", "/dev/shm", "tmpfs", 0, NULL) < 0)
        perror("mount");

    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
        perror("mount");

    pid_t pid = spawn("/bin/moused");
    if (pid > 0) {
        waitpid(pid, NULL, 0);
        spawn("/bin/mouse-cursor");
    }

    for (;;)
        waitpid(-1, NULL, 0); // Reap zombies

    UNREACHABLE();
}
