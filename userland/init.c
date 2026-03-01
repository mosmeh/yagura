#include <dirent.h>
#include <fcntl.h>
#include <linux/kd.h>
#include <linux/major.h>
#include <panic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/limits.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t spawn(const char* filename, char* const argv[]) {
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
        if (execve(filename, argv, environ) < 0) {
            perror("execve");
            abort();
        }
    }
    return pid;
}

static pid_t spawn_no_arg(char* filename) {
    return spawn(filename, (char* const[]){filename, NULL});
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

    ASSERT_OK(mount("devtmpfs", "/dev", "devtmpfs", 0, NULL));

    int fd = open("/dev/console", O_RDWR);
    ASSERT(fd == STDIN_FILENO);
    ASSERT_OK(dup2(fd, STDOUT_FILENO));
    ASSERT_OK(dup2(fd, STDERR_FILENO));

    set_console_palette(fd);

    if (chdir("/root") < 0)
        perror("chdir");

    if (setenv("HOME", "/root", 1) < 0)
        perror("setenv");

    DIR* dev_dir = ASSERT(opendir("/dev"));
    for (;;) {
        struct dirent* entry = readdir(dev_dir);
        if (!entry)
            break;
        if (entry->d_type != DT_CHR)
            continue;

        char tty[PATH_MAX];
        ASSERT((size_t)snprintf(tty, sizeof(tty), "/dev/%s", entry->d_name) <
               sizeof(tty));

        struct stat st;
        if (stat(tty, &st) < 0) {
            perror("stat");
            continue;
        }
        if (!S_ISCHR(st.st_mode) || major(st.st_rdev) != TTY_MAJOR ||
            minor(st.st_rdev) == 0)
            continue;

        static char* const getty = "/bin/getty";
        spawn(getty, (char* const[]){getty, tty, NULL});
    }
    closedir(dev_dir);

    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0)
        perror("mount");

    if (mkdir("/dev/shm", 0755) < 0)
        perror("mkdir");
    else if (mount("tmpfs", "/dev/shm", "tmpfs", 0, NULL) < 0)
        perror("mount");

    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
        perror("mount");

    pid_t pid = spawn_no_arg("/bin/moused");
    if (pid > 0) {
        waitpid(pid, NULL, 0);
        spawn_no_arg("/bin/mouse-cursor");
    }

    for (;;)
        wait(NULL); // Reap zombies

    UNREACHABLE();
}
