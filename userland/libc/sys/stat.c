#include "../private.h"
#include <err.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

MAYBE_UNUSED static void linux_stat_to_stat(const struct linux_stat* lstat,
                                            struct stat* stat) {
    *stat = (struct stat){
        .st_dev = lstat->st_dev,
        .st_ino = lstat->st_ino,
        .st_mode = lstat->st_mode,
        .st_nlink = lstat->st_nlink,
        .st_uid = lstat->st_uid,
        .st_gid = lstat->st_gid,
        .st_rdev = lstat->st_rdev,
        .st_size = lstat->st_size,
        .st_blksize = lstat->st_blksize,
        .st_blocks = lstat->st_blocks,
        .st_atim = {lstat->st_atime, lstat->st_atime_nsec},
        .st_mtim = {lstat->st_mtime, lstat->st_mtime_nsec},
        .st_ctim = {lstat->st_ctime, lstat->st_ctime_nsec},
    };
}

MAYBE_UNUSED static void
linux_stat64_to_stat(const struct linux_stat64* lstat64, struct stat* stat) {
    *stat = (struct stat){
        .st_dev = lstat64->st_dev,
        .st_ino = lstat64->st_ino,
        .st_mode = lstat64->st_mode,
        .st_nlink = lstat64->st_nlink,
        .st_uid = lstat64->st_uid,
        .st_gid = lstat64->st_gid,
        .st_rdev = lstat64->st_rdev,
        .st_size = lstat64->st_size,
        .st_blksize = lstat64->st_blksize,
        .st_blocks = lstat64->st_blocks,
        .st_atim = {lstat64->st_atime, lstat64->st_atime_nsec},
        .st_mtim = {lstat64->st_mtime, lstat64->st_mtime_nsec},
        .st_ctim = {lstat64->st_ctime, lstat64->st_ctime_nsec},
    };
}

int stat(const char* pathname, struct stat* buf) {
    int rc;
#ifdef SYS_stat64
    struct linux_stat64 stat;
    rc = SYSCALL2(stat64, pathname, &stat);
    if (IS_ERR(rc))
        return __syscall_return(rc);
    linux_stat64_to_stat(&stat, buf);
#else
    struct linux_stat stat;
    rc = SYSCALL2(stat, pathname, &stat);
    if (IS_ERR(rc))
        return __syscall_return(rc);
    linux_stat_to_stat(&stat, buf);
#endif
    return rc;
}

int lstat(const char* pathname, struct stat* buf) {
    int rc;
#ifdef SYS_lstat64
    struct linux_stat64 stat;
    rc = SYSCALL2(lstat64, pathname, &stat);
    if (IS_ERR(rc))
        return __syscall_return(rc);
    linux_stat64_to_stat(&stat, buf);
#else
    struct linux_stat stat;
    rc = SYSCALL2(lstat, pathname, &stat);
    if (IS_ERR(rc))
        return __syscall_return(rc);
    linux_stat_to_stat(&stat, buf);
#endif
    return rc;
}

int fstat(int fd, struct stat* buf) {
    int rc;
#ifdef SYS_fstat64
    struct linux_stat64 stat;
    rc = SYSCALL2(fstat64, fd, &stat);
    if (IS_ERR(rc))
        return __syscall_return(rc);
    linux_stat64_to_stat(&stat, buf);
#else
    struct linux_stat stat;
    rc = SYSCALL2(fstat, fd, &stat);
    if (IS_ERR(rc))
        return __syscall_return(rc);
    linux_stat_to_stat(&stat, buf);
#endif
    return rc;
}

int fstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags) {
    int rc;
#ifdef SYS_newfstatat
    struct linux_stat stat;
    rc = SYSCALL4(newfstatat, dirfd, pathname, &stat, flags);
    if (IS_ERR(rc))
        return __syscall_return(rc);
    linux_stat_to_stat(&stat, statbuf);
#else
    struct linux_stat64 stat;
    rc = SYSCALL4(fstatat64, dirfd, pathname, &stat, flags);
    if (IS_ERR(rc))
        return __syscall_return(rc);
    linux_stat64_to_stat(&stat, statbuf);
#endif
    return rc;
}

int statx(int dirfd, const char* pathname, int flags, unsigned int mask,
          struct statx* statxbuf) {
    return __syscall_return(
        SYSCALL5(statx, dirfd, pathname, flags, mask, statxbuf));
}

int mkdir(const char* pathname, mode_t mode) {
    return __syscall_return(SYSCALL2(mkdir, pathname, mode));
}

int mkdirat(int dirfd, const char* pathname, mode_t mode) {
    return __syscall_return(SYSCALL3(mkdirat, dirfd, pathname, mode));
}

int mknod(const char* pathname, mode_t mode, dev_t dev) {
    return __syscall_return(SYSCALL3(mknod, pathname, mode, dev));
}

int mknodat(int dirfd, const char* pathname, mode_t mode, dev_t dev) {
    return __syscall_return(SYSCALL4(mknodat, dirfd, pathname, mode, dev));
}

int mkfifo(const char* pathname, mode_t mode) {
    return mknod(pathname, mode | S_IFIFO, 0);
}

int chmod(const char* pathname, mode_t mode) {
    return __syscall_return(SYSCALL2(chmod, pathname, mode));
}

int fchmod(int fd, mode_t mode) {
    return __syscall_return(SYSCALL2(fchmod, fd, mode));
}

int fchmodat(int dirfd, const char* pathname, mode_t mode, int flags) {
    if (flags)
        return __syscall_return(-EINVAL);
    return __syscall_return(SYSCALL3(fchmodat, dirfd, pathname, mode));
}

mode_t umask(mode_t mask) { return __syscall_return(SYSCALL1(umask, mask)); }
