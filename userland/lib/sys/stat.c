#include "stat.h"
#include <err.h>
#include <errno.h>
#include <private.h>
#include <unistd.h>

static void stat64_to_stat(const struct linux_stat64* stat64,
                           struct stat* stat) {
    *stat = (struct stat){
        .st_dev = stat64->st_dev,
        .st_ino = stat64->st_ino,
        .st_mode = stat64->st_mode,
        .st_nlink = stat64->st_nlink,
        .st_uid = stat64->st_uid,
        .st_gid = stat64->st_gid,
        .st_rdev = stat64->st_rdev,
        .st_size = stat64->st_size,
        .st_blksize = stat64->st_blksize,
        .st_blocks = stat64->st_blocks,
        .st_atim = {stat64->st_atime, stat64->st_atime_nsec},
        .st_mtim = {stat64->st_mtime, stat64->st_mtime_nsec},
        .st_ctim = {stat64->st_ctime, stat64->st_ctime_nsec},
    };
}

int stat(const char* pathname, struct stat* buf) {
    struct linux_stat64 stat64;
    int rc = SYSCALL2(stat64, pathname, &stat64);
    if (IS_ERR(rc)) {
        errno = -rc;
        return -1;
    }
    stat64_to_stat(&stat64, buf);
    return rc;
}

int lstat(const char* pathname, struct stat* buf) {
    struct linux_stat64 stat64;
    int rc = SYSCALL2(lstat64, pathname, &stat64);
    if (IS_ERR(rc)) {
        errno = -rc;
        return -1;
    }
    stat64_to_stat(&stat64, buf);
    return rc;
}

int fstat(int fd, struct stat* buf) {
    struct linux_stat64 stat64;
    int rc = SYSCALL2(fstat64, fd, &stat64);
    if (IS_ERR(rc)) {
        errno = -rc;
        return -1;
    }
    stat64_to_stat(&stat64, buf);
    return rc;
}

int mkdir(const char* pathname, mode_t mode) {
    return __syscall_return(SYSCALL2(mkdir, pathname, mode));
}

int mkfifo(const char* pathname, mode_t mode) {
    return mknod(pathname, mode | S_IFIFO, 0);
}
