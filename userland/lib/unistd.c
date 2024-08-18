#include "unistd.h"
#include "errno.h"
#include "fcntl.h"
#include "panic.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/ioctl.h"
#include "sys/reboot.h"
#include "time.h"
#include <private.h>

char** environ;

pid_t getpid(void) { RETURN_WITH_ERRNO(pid_t, SYSCALL0(getpid)); }

pid_t gettid(void) { RETURN_WITH_ERRNO(pid_t, SYSCALL0(gettid)); }

int setpgid(pid_t pid, pid_t pgid) {
    RETURN_WITH_ERRNO(int, SYSCALL2(setpgid, pid, pgid));
}

pid_t getpgid(pid_t pid) { RETURN_WITH_ERRNO(pid_t, SYSCALL1(getpgid, pid)); }

pid_t fork(void) { RETURN_WITH_ERRNO(pid_t, SYSCALL0(fork)); }

int execve(const char* pathname, char* const argv[], char* const envp[]) {
    RETURN_WITH_ERRNO(int, SYSCALL3(execve, pathname, argv, envp));
}

int execvpe(const char* file, char* const argv[], char* const envp[]) {
    if (strchr(file, '/'))
        return execve(file, argv, envp);

    const char* path = getenv("PATH");
    if (!path)
        path = "/bin";
    char* dup_path = strdup(path);
    if (!dup_path)
        return -1;

    int saved_errno = errno;

    static const char* sep = ":";
    char* saved_ptr;
    for (const char* part = strtok_r(dup_path, sep, &saved_ptr); part;
         part = strtok_r(NULL, sep, &saved_ptr)) {
        static char buf[1024];
        ASSERT(sprintf(buf, "%s/%s", part, file) > 0);

        int rc = execve(buf, argv, envp);
        ASSERT(rc < 0);
        if (errno != ENOENT) {
            free(dup_path);
            return -1;
        }
        errno = saved_errno;
    }
    free(dup_path);

    errno = ENOENT;
    return -1;
}

int close(int fd) { RETURN_WITH_ERRNO(int, SYSCALL1(close, fd)); }

ssize_t read(int fd, void* buf, size_t count) {
    RETURN_WITH_ERRNO(ssize_t, SYSCALL3(read, fd, buf, count));
}

ssize_t write(int fd, const void* buf, size_t count) {
    RETURN_WITH_ERRNO(ssize_t, SYSCALL3(write, fd, buf, count));
}

int ftruncate(int fd, off_t length) {
    RETURN_WITH_ERRNO(int, SYSCALL2(ftruncate, fd, length));
}

off_t lseek(int fd, off_t offset, int whence) {
    RETURN_WITH_ERRNO(off_t, SYSCALL3(lseek, fd, offset, whence));
}

int mknod(const char* pathname, mode_t mode, dev_t dev) {
    RETURN_WITH_ERRNO(int, SYSCALL3(mknod, pathname, mode, dev));
}

int link(const char* oldpath, const char* newpath) {
    RETURN_WITH_ERRNO(int, SYSCALL2(link, oldpath, newpath));
}

int symlink(const char* target, const char* linkpath) {
    RETURN_WITH_ERRNO(int, SYSCALL2(symlink, target, linkpath));
}

int unlink(const char* pathname) {
    RETURN_WITH_ERRNO(int, SYSCALL1(unlink, pathname));
}

ssize_t readlink(const char* pathname, char* buf, size_t bufsiz) {
    RETURN_WITH_ERRNO(ssize_t, SYSCALL3(readlink, pathname, buf, bufsiz));
}

int rename(const char* oldpath, const char* newpath) {
    RETURN_WITH_ERRNO(int, SYSCALL2(rename, oldpath, newpath));
}

int rmdir(const char* pathname) {
    RETURN_WITH_ERRNO(int, SYSCALL1(rmdir, pathname));
}

int dup(int oldfd) { return fcntl(oldfd, F_DUPFD); }

int dup2(int oldfd, int newfd) {
    RETURN_WITH_ERRNO(int, SYSCALL2(dup2, oldfd, newfd));
}

int pipe(int pipefd[2]) { RETURN_WITH_ERRNO(int, SYSCALL1(pipe, pipefd)); }

char* getcwd(char* buf, size_t size) {
    int rc = SYSCALL2(getcwd, buf, size);
    if (IS_ERR(rc)) {
        errno = -rc;
        return NULL;
    }
    return buf;
}

int chdir(const char* path) { RETURN_WITH_ERRNO(int, SYSCALL1(chdir, path)); }

pid_t tcgetpgrp(int fd) { return ioctl(fd, TIOCGPGRP, NULL); }

int tcsetpgrp(int fd, pid_t pgrp) { return ioctl(fd, TIOCSPGRP, &pgrp); }

unsigned int sleep(unsigned int seconds) {
    struct timespec req = {.tv_sec = seconds, .tv_nsec = 0};
    struct timespec rem;
    if (nanosleep(&req, &rem) < 0)
        return rem.tv_sec;
    return 0;
}

int usleep(useconds_t usec) {
    struct timespec req = {
        .tv_sec = usec / 1000000,
        .tv_nsec = (usec % 1000000) * 1000LL,
    };
    return nanosleep(&req, NULL);
}

int reboot(int howto) {
    RETURN_WITH_ERRNO(int, SYSCALL4(reboot, LINUX_REBOOT_MAGIC1,
                                    LINUX_REBOOT_MAGIC2, howto, NULL));
}

long sysconf(int name) { RETURN_WITH_ERRNO(long, SYSCALL1(sysconf, name)); }
