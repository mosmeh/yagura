#include <common/string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <linux/major.h>
#include <panic.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/limits.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static const char* const default_dir = "/bin/tests";

// panic() calls abort(), which raises SIGABRT.
// Signals can be sent to init process only when signal handlers are explicitly
// installed, so we need to install a handler for SIGABRT when running as init.
static void sigabrt_handler(int signum) {
    (void)signum;
    _exit(EXIT_FAILURE);
}

static void spawn(char* filename) {
    pid_t pid = ASSERT_OK(fork());
    if (pid == 0) {
        char* argv[] = {filename, NULL};
        static char* const envp[] = {NULL};
        if (execve(argv[0], argv, envp) < 0) {
            perror("execve");
            abort();
        }
    }

    int status;
    ASSERT_OK(waitpid(pid, &status, 0));
    ASSERT(WIFEXITED(status));
    ASSERT(WEXITSTATUS(status) == EXIT_SUCCESS);
}

static void run(const char* dir_path) {
    DIR* dir = ASSERT(opendir(dir_path));
    size_t num_tests_passed = 0;
    for (;;) {
        errno = 0;
        struct dirent* dent = readdir(dir);
        if (!dent) {
            ASSERT(errno == 0);
            break;
        }
        if (dent->d_type != DT_REG)
            continue;
        if (!strcmp(dent->d_name, "run"))
            continue;
        printf("[TEST] %s\n", dent->d_name);
        char path[PATH_MAX];
        (void)snprintf(path, sizeof(path), "%s/%s", dir_path, dent->d_name);
        spawn(path);
        ++num_tests_passed;
    }
    closedir(dir);
    ASSERT(num_tests_passed > 0);
    puts("ALL TESTS PASSED");
}

int main(int argc, char** argv) {
    if (getpid() != 1) {
        if (argc > 0 && argv[0][0] == '/')
            run(dirname(argv[0]));
        else
            run(default_dir);
        return EXIT_SUCCESS;
    }

    ASSERT(signal(SIGABRT, sigabrt_handler) == SIG_DFL);

    ASSERT_OK(mount("tmpfs", "/dev", "tmpfs", 0, NULL));

    ASSERT_OK(mknod("/dev/console", S_IFCHR | 0600, makedev(TTYAUX_MAJOR, 1)));
    int fd = open("/dev/console", O_RDWR);
    ASSERT(fd == STDIN_FILENO);
    ASSERT_OK(dup2(fd, STDOUT_FILENO));
    ASSERT_OK(dup2(fd, STDERR_FILENO));

    run(default_dir);

    reboot(RB_POWER_OFF);
    UNREACHABLE();
}
