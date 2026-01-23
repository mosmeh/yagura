#include "private.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <panic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/limits.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

char** environ;

pid_t getpid(void) { return __syscall_return(SYSCALL0(getpid)); }

pid_t getppid(void) { return __syscall_return(SYSCALL0(getppid)); }

pid_t gettid(void) { return __syscall_return(SYSCALL0(gettid)); }

int setpgid(pid_t pid, pid_t pgid) {
    return __syscall_return(SYSCALL2(setpgid, pid, pgid));
}

pid_t getpgid(pid_t pid) { return __syscall_return(SYSCALL1(getpgid, pid)); }

pid_t getpgrp(void) { return __syscall_return(SYSCALL0(getpgrp)); }

pid_t fork(void) { return __syscall_return(SYSCALL0(fork)); }

int execve(const char* pathname, char* const argv[], char* const envp[]) {
    return __syscall_return(SYSCALL3(execve, pathname, argv, envp));
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

uid_t getuid(void) { return __syscall_return(SYSCALL0(getuid32)); }

uid_t geteuid(void) { return __syscall_return(SYSCALL0(geteuid32)); }

gid_t getgid(void) { return __syscall_return(SYSCALL0(getgid32)); }

gid_t getegid(void) { return __syscall_return(SYSCALL0(getegid32)); }

int access(const char* pathname, int mode) {
    return __syscall_return(SYSCALL2(access, pathname, mode));
}

int faccessat(int dirfd, const char* pathname, int mode, int flags) {
    if (flags & ~AT_SYMLINK_NOFOLLOW)
        return __syscall_return(-EINVAL);
    if (flags & AT_SYMLINK_NOFOLLOW) {
        // File permissions are not implemented. Just check the existence.
        struct stat buf;
        return fstatat(dirfd, pathname, &buf, AT_SYMLINK_NOFOLLOW);
    }
    return __syscall_return(SYSCALL3(faccessat, dirfd, pathname, mode));
}

int close(int fd) { return __syscall_return(SYSCALL1(close, fd)); }

ssize_t read(int fd, void* buf, size_t count) {
    return __syscall_return(SYSCALL3(read, fd, buf, count));
}

ssize_t write(int fd, const void* buf, size_t count) {
    return __syscall_return(SYSCALL3(write, fd, buf, count));
}

ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
    return __syscall_return(SYSCALL5(pread64, fd, buf, count, offset, 0));
}

ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset) {
    return __syscall_return(SYSCALL5(pwrite64, fd, buf, count, offset, 0));
}

int truncate(const char* path, off_t length) {
    return __syscall_return(SYSCALL2(truncate, path, length));
}

int ftruncate(int fd, off_t length) {
    return __syscall_return(SYSCALL2(ftruncate, fd, length));
}

off_t lseek(int fd, off_t offset, int whence) {
    return __syscall_return(SYSCALL3(lseek, fd, offset, whence));
}

int link(const char* oldpath, const char* newpath) {
    return __syscall_return(SYSCALL2(link, oldpath, newpath));
}

int linkat(int olddirfd, const char* oldpath, int newdirfd, const char* newpath,
           int flags) {
    return __syscall_return(
        SYSCALL5(linkat, olddirfd, oldpath, newdirfd, newpath, flags));
}

int symlink(const char* target, const char* linkpath) {
    return __syscall_return(SYSCALL2(symlink, target, linkpath));
}

int symlinkat(const char* target, int newdirfd, const char* linkpath) {
    return __syscall_return(SYSCALL3(symlinkat, target, newdirfd, linkpath));
}

int unlink(const char* pathname) {
    return __syscall_return(SYSCALL1(unlink, pathname));
}

int unlinkat(int dirfd, const char* pathname, int flags) {
    return __syscall_return(SYSCALL3(unlinkat, dirfd, pathname, flags));
}

ssize_t readlink(const char* pathname, char* buf, size_t bufsiz) {
    return __syscall_return(SYSCALL3(readlink, pathname, buf, bufsiz));
}

ssize_t readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsiz) {
    return __syscall_return(SYSCALL4(readlinkat, dirfd, pathname, buf, bufsiz));
}

int rmdir(const char* pathname) {
    return __syscall_return(SYSCALL1(rmdir, pathname));
}

int dup(int oldfd) { return __syscall_return(SYSCALL1(dup, oldfd)); }

int dup2(int oldfd, int newfd) {
    return __syscall_return(SYSCALL2(dup2, oldfd, newfd));
}

int dup3(int oldfd, int newfd, int flags) {
    return __syscall_return(SYSCALL3(dup3, oldfd, newfd, flags));
}

int pipe(int pipefd[2]) { return __syscall_return(SYSCALL1(pipe, pipefd)); }

int pipe2(int pipefd[2], int flags) {
    return __syscall_return(SYSCALL2(pipe2, pipefd, flags));
}

void sync(void) { SYSCALL0(sync); }

int syncfs(int fd) { return __syscall_return(SYSCALL1(syncfs, fd)); }

int fsync(int fd) { return __syscall_return(SYSCALL1(fsync, fd)); }

int fdatasync(int fd) { return __syscall_return(SYSCALL1(fdatasync, fd)); }

int chroot(const char* path) {
    return __syscall_return(SYSCALL1(chroot, path));
}

char* getcwd(char* buf, size_t size) {
    if (size == 0) {
        errno = EINVAL;
        return NULL;
    }
    int rc = SYSCALL2(getcwd, buf, size);
    if (IS_ERR(rc)) {
        errno = -rc;
        return NULL;
    }
    return buf;
}

int chdir(const char* path) { return __syscall_return(SYSCALL1(chdir, path)); }

pid_t tcgetpgrp(int fd) {
    pid_t pgrp;
    if (ioctl(fd, TIOCGPGRP, &pgrp) < 0)
        return -1;
    return pgrp;
}

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

int pause(void) { return __syscall_return(SYSCALL0(pause)); }

int gethostname(char* name, size_t len) {
    struct utsname buf;
    if (uname(&buf) < 0)
        return -1;
    strlcpy(name, buf.nodename, len);
    return 0;
}

int sethostname(const char* name, size_t len) {
    return __syscall_return(SYSCALL2(sethostname, name, len));
}

int getdomainname(char* name, size_t len) {
    struct utsname buf;
    if (uname(&buf) < 0)
        return -1;
    strlcpy(name, buf.domainname, len);
    return 0;
}

int setdomainname(const char* name, size_t len) {
    return __syscall_return(SYSCALL2(setdomainname, name, len));
}

int reboot(int howto) {
    return __syscall_return(SYSCALL4(reboot, LINUX_REBOOT_MAGIC1,
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
        errno = EINVAL;
        return -1;
    }
}

long syscall(long num, ...) {
    va_list args;
    va_start(args, num);
    long arg1 = va_arg(args, long);
    long arg2 = va_arg(args, long);
    long arg3 = va_arg(args, long);
    long arg4 = va_arg(args, long);
    long arg5 = va_arg(args, long);
    long arg6 = va_arg(args, long);
    va_end(args);
    return __syscall_return(__syscall(num, arg1, arg2, arg3, arg4, arg5, arg6));
}
