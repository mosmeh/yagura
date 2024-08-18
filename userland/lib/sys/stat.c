#include "stat.h"
#include <private.h>
#include <unistd.h>

static void linux_stat_to_stat(const struct linux_stat* linux_stat,
                               struct stat* stat) {
    *stat = (struct stat){
        .st_dev = linux_stat->st_dev,
        .st_ino = linux_stat->st_ino,
        .st_mode = linux_stat->st_mode,
        .st_nlink = linux_stat->st_nlink,
        .st_uid = linux_stat->st_uid,
        .st_gid = linux_stat->st_gid,
        .st_rdev = linux_stat->st_rdev,
        .st_size = linux_stat->st_size,
        .st_blksize = linux_stat->st_blksize,
        .st_blocks = linux_stat->st_blocks,
        .st_atim = {linux_stat->st_atime, linux_stat->st_atime_nsec},
        .st_mtim = {linux_stat->st_mtime, linux_stat->st_mtime_nsec},
        .st_ctim = {linux_stat->st_ctime, linux_stat->st_ctime_nsec},
    };
}

int stat(const char* pathname, struct stat* buf) {
    struct linux_stat linux_stat;
    int rc = SYSCALL2(stat, pathname, &linux_stat);
    if (IS_ERR(rc)) {
        errno = -rc;
        return -1;
    }
    linux_stat_to_stat(&linux_stat, buf);
    return rc;
}

int lstat(const char* pathname, struct stat* buf) {
    struct linux_stat linux_stat;
    int rc = SYSCALL2(lstat, pathname, &linux_stat);
    if (IS_ERR(rc)) {
        errno = -rc;
        return -1;
    }
    linux_stat_to_stat(&linux_stat, buf);
    return rc;
}

int mkdir(const char* pathname, mode_t mode) {
    RETURN_WITH_ERRNO(int, SYSCALL2(mkdir, pathname, mode));
}

int mkfifo(const char* pathname, mode_t mode) {
    return mknod(pathname, mode | S_IFIFO, 0);
}
