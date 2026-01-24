#include <common/stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kd.h>
#include <linux/major.h>
#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
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
    if (mknod(file->pathname, file->mode | 0777, file->dev) < 0) {
        perror("mknod");
        return false;
    }

    int fd = open(file->pathname, 0);
    if (fd >= 0) {
        if (fchmod(fd, file->mode) < 0)
            perror("fchmod");
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

static int set_console_palette(int fd) {
    static const unsigned char cmap[] = {
        0x19, 0x19, 0x19, 0xcc, 0x00, 0x00, 0x4e, 0x9a, 0x06, 0xc4, 0xa0, 0x00,
        0x34, 0x65, 0xa4, 0x75, 0x50, 0x7b, 0x06, 0x98, 0x9a, 0xd0, 0xd0, 0xd0,
        0x55, 0x57, 0x53, 0xef, 0x29, 0x29, 0x8a, 0xe2, 0x34, 0xfc, 0xe9, 0x4f,
        0x72, 0x9f, 0xcf, 0xad, 0x7f, 0xa8, 0x34, 0xe2, 0xe2, 0xee, 0xee, 0xec,
    };
    return ioctl(fd, PIO_CMAP, cmap);
}

int main(void) {
    ASSERT(getpid() == 1);

    ASSERT_OK(mount("tmpfs", "/dev", "tmpfs", 0, NULL));

    ASSERT_OK(mknod("/dev/console", S_IFCHR | 0600, makedev(TTYAUX_MAJOR, 1)));
    int fd = open("/dev/console", O_RDWR);
    ASSERT(fd == STDIN_FILENO);
    ASSERT_OK(dup2(fd, STDOUT_FILENO));
    ASSERT_OK(dup2(fd, STDERR_FILENO));

    set_console_palette(fd);

    if (chdir("/root") < 0)
        perror("chdir");

    static const struct device_file device_files[] = {
        {"/dev/null", S_IFCHR | 0666, makedev(MEM_MAJOR, 3)},
        {"/dev/zero", S_IFCHR | 0666, makedev(MEM_MAJOR, 5)},
        {"/dev/full", S_IFCHR | 0666, makedev(MEM_MAJOR, 7)},
        {"/dev/random", S_IFCHR | 0666, makedev(MEM_MAJOR, 8)},
        {"/dev/urandom", S_IFCHR | 0666, makedev(MEM_MAJOR, 9)},
        {"/dev/kmsg", S_IFCHR | 0644, makedev(MEM_MAJOR, 11)},
        {"/dev/psaux", S_IFCHR | 0660, makedev(MISC_MAJOR, 1)},
        {"/dev/dsp", S_IFCHR | 0660, makedev(SOUND_MAJOR, 3)},
        {"/dev/fb0", S_IFCHR | 0660, makedev(FB_MAJOR, 0)},
    };
    for (size_t i = 0; i < ARRAY_SIZE(device_files); ++i)
        try_mknod(&device_files[i]);

    for (size_t i = 0; i < 64; ++i) {
        char pathname[16];
        (void)sprintf(pathname, "/dev/tty%zu", i);
        struct device_file file = {
            .pathname = pathname,
            .mode = S_IFCHR | 0620,
            .dev = makedev(TTY_MAJOR, i),
        };
        if (try_mknod(&file))
            spawn_getty(pathname);
    }

    for (size_t i = 0; i < 4; ++i) {
        char pathname[16] = "/dev/ttyS";
        pathname[9] = '0' + i;
        struct device_file file = {
            .pathname = pathname,
            .mode = S_IFCHR | 0660,
            .dev = makedev(TTY_MAJOR, 64 + i),
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
            .mode = S_IFBLK | 0660,
            .dev = makedev(254, i),
        };
        try_mknod(&file);
    }

    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0)
        perror("mount");

    if (mkdir("/dev/shm", 0755) < 0)
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
