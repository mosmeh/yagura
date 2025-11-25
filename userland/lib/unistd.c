#include "unistd.h"
#include "fcntl.h"
#include "panic.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/auxv.h"
#include "sys/ioctl.h"
#include "sys/reboot.h"
#include "sys/utsname.h"
#include "time.h"
#include <private.h>
#include <sys/limits.h>

char** environ;

pid_t getpid(void) { RETURN_WITH_ERRNO(pid_t, SYSCALL0(getpid)); }

pid_t getppid(void) { RETURN_WITH_ERRNO(pid_t, SYSCALL0(getppid)); }

pid_t gettid(void) { RETURN_WITH_ERRNO(pid_t, SYSCALL0(gettid)); }

int setpgid(pid_t pid, pid_t pgid) {
    RETURN_WITH_ERRNO(int, SYSCALL2(setpgid, pid, pgid));
}

pid_t getpgid(pid_t pid) { RETURN_WITH_ERRNO(pid_t, SYSCALL1(getpgid, pid)); }

pid_t getpgrp(void) { RETURN_WITH_ERRNO(pid_t, SYSCALL0(getpgrp)); }

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

uid_t getuid(void) { RETURN_WITH_ERRNO(uid_t, SYSCALL0(getuid32)); }

uid_t geteuid(void) { RETURN_WITH_ERRNO(uid_t, SYSCALL0(geteuid32)); }

gid_t getgid(void) { RETURN_WITH_ERRNO(gid_t, SYSCALL0(getgid32)); }

gid_t getegid(void) { RETURN_WITH_ERRNO(gid_t, SYSCALL0(getegid32)); }

int access(const char* pathname, int mode) {
    RETURN_WITH_ERRNO(int, SYSCALL2(access, pathname, mode));
}

int close(int fd) { RETURN_WITH_ERRNO(int, SYSCALL1(close, fd)); }

ssize_t read(int fd, void* buf, size_t count) {
    RETURN_WITH_ERRNO(ssize_t, SYSCALL3(read, fd, buf, count));
}

ssize_t write(int fd, const void* buf, size_t count) {
    RETURN_WITH_ERRNO(ssize_t, SYSCALL3(write, fd, buf, count));
}

ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
    RETURN_WITH_ERRNO(ssize_t, SYSCALL5(pread64, fd, buf, count, offset, 0));
}

ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset) {
    RETURN_WITH_ERRNO(ssize_t, SYSCALL5(pwrite64, fd, buf, count, offset, 0));
}

int truncate(const char* path, off_t length) {
    RETURN_WITH_ERRNO(int, SYSCALL2(truncate, path, length));
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

int dup3(int oldfd, int newfd, int flags) {
    RETURN_WITH_ERRNO(int, SYSCALL3(dup3, oldfd, newfd, flags));
}

int pipe(int pipefd[2]) { RETURN_WITH_ERRNO(int, SYSCALL1(pipe, pipefd)); }

int pipe2(int pipefd[2], int flags) {
    RETURN_WITH_ERRNO(int, SYSCALL2(pipe2, pipefd, flags));
}

void sync(void) { SYSCALL0(sync); }

int syncfs(int fd) { RETURN_WITH_ERRNO(int, SYSCALL1(syncfs, fd)); }

int fsync(int fd) { RETURN_WITH_ERRNO(int, SYSCALL1(fsync, fd)); }

int fdatasync(int fd) { RETURN_WITH_ERRNO(int, SYSCALL1(fdatasync, fd)); }

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

int pause(void) { RETURN_WITH_ERRNO(int, SYSCALL0(pause)); }

int gethostname(char* name, size_t len) {
    struct utsname buf;
    if (uname(&buf) < 0)
        return -1;
    strlcpy(name, buf.nodename, len);
    return 0;
}

int sethostname(const char* name, size_t len) {
    RETURN_WITH_ERRNO(int, SYSCALL2(sethostname, name, len));
}

int getdomainname(char* name, size_t len) {
    struct utsname buf;
    if (uname(&buf) < 0)
        return -1;
    strlcpy(name, buf.domainname, len);
    return 0;
}

int setdomainname(const char* name, size_t len) {
    RETURN_WITH_ERRNO(int, SYSCALL2(setdomainname, name, len));
}

int reboot(int howto) {
    RETURN_WITH_ERRNO(int, SYSCALL4(reboot, LINUX_REBOOT_MAGIC1,
                                    LINUX_REBOOT_MAGIC2, howto, NULL));
}

long sysconf(int name) {
    switch (name) {
    case _SC_ARG_MAX:
        return ARG_MAX;
    case _SC_CLK_TCK:
        return getauxval(AT_CLKTCK);
    case _SC_MONOTONIC_CLOCK:
        return 1;
    case _SC_OPEN_MAX:
        return OPEN_MAX;
    case _SC_PAGESIZE:
        return getauxval(AT_PAGESZ);
    case _SC_SYMLOOP_MAX:
        return SYMLOOP_MAX;
    default:
        return -EINVAL;
    }
}
