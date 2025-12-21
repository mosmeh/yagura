#include "private.h"
#include <kernel/api/fcntl.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task.h>

NODISCARD static int stat(const char* user_pathname, struct kstat* buf) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;
    return vfs_stat(pathname, buf, 0);
}

NODISCARD static int lstat(const char* user_pathname, struct kstat* buf) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;
    return vfs_stat(pathname, buf, O_NOFOLLOW | O_NOFOLLOW_NOERROR);
}

NODISCARD static int fstat(int fd, struct kstat* buf) {
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return inode_stat(file->inode, buf);
}

NODISCARD static int copy_stat_to_user_old(const struct kstat* stat,
                                           struct linux_old_stat* user_buf) {
    struct linux_old_stat old_stat = {
        .st_dev = stat->st_dev,
        .st_ino = stat->st_ino,
        .st_mode = stat->st_mode,
        .st_nlink = stat->st_nlink,
        .st_uid = stat->st_uid,
        .st_gid = stat->st_gid,
        .st_rdev = stat->st_rdev,
        .st_size = stat->st_size,
        .st_atime = stat->st_atim.tv_sec,
        .st_mtime = stat->st_mtim.tv_sec,
        .st_ctime = stat->st_ctim.tv_sec,
    };

    if (old_stat.st_ino != stat->st_ino)
        return -EOVERFLOW;
    if (old_stat.st_nlink != stat->st_nlink)
        return -EOVERFLOW;

    if (copy_to_user(user_buf, &old_stat, sizeof(struct linux_old_stat)))
        return -EFAULT;
    return 0;
}

int sys_stat(const char* user_pathname, struct linux_old_stat* user_buf) {
    struct kstat buf;
    int rc = stat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user_old(&buf, user_buf);
}

int sys_lstat(const char* user_pathname, struct linux_old_stat* user_buf) {
    struct kstat buf;
    int rc = lstat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user_old(&buf, user_buf);
}

int sys_fstat(int fd, struct linux_old_stat* user_buf) {
    struct kstat buf;
    int rc = fstat(fd, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user_old(&buf, user_buf);
}

NODISCARD static int copy_stat_to_user(const struct kstat* stat,
                                       struct linux_stat* user_buf) {
    struct linux_stat linux_stat = {
        .st_dev = stat->st_dev,
        .st_ino = stat->st_ino,
        .st_mode = stat->st_mode,
        .st_nlink = stat->st_nlink,
        .st_uid = stat->st_uid,
        .st_gid = stat->st_gid,
        .st_rdev = stat->st_rdev,
        .st_size = stat->st_size,
        .st_blksize = stat->st_blksize,
        .st_blocks = stat->st_blocks,
        .st_atime = stat->st_atim.tv_sec,
        .st_atime_nsec = stat->st_atim.tv_nsec,
        .st_mtime = stat->st_mtim.tv_sec,
        .st_mtime_nsec = stat->st_mtim.tv_nsec,
        .st_ctime = stat->st_ctim.tv_sec,
        .st_ctime_nsec = stat->st_ctim.tv_nsec,
    };

    if (linux_stat.st_nlink != stat->st_nlink)
        return -EOVERFLOW;

    if (copy_to_user(user_buf, &linux_stat, sizeof(struct linux_stat)))
        return -EFAULT;
    return 0;
}

int sys_newstat(const char* user_pathname, struct linux_stat* user_buf) {
    struct kstat buf;
    int rc = stat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user(&buf, user_buf);
}

int sys_newlstat(const char* user_pathname, struct linux_stat* user_buf) {
    struct kstat buf;
    int rc = lstat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user(&buf, user_buf);
}

int sys_newfstat(int fd, struct linux_stat* user_buf) {
    struct kstat buf;
    int rc = fstat(fd, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user(&buf, user_buf);
}

NODISCARD static int copy_stat_to_user64(const struct kstat* stat,
                                         struct linux_stat64* user_buf) {
    struct linux_stat64 stat64 = {
        .st_dev = stat->st_dev,
        .st_ino = stat->st_ino,
        .__st_ino = stat->st_ino,
        .st_mode = stat->st_mode,
        .st_nlink = stat->st_nlink,
        .st_uid = stat->st_uid,
        .st_gid = stat->st_gid,
        .st_rdev = stat->st_rdev,
        .st_size = stat->st_size,
        .st_blksize = stat->st_blksize,
        .st_blocks = stat->st_blocks,
        .st_atime = stat->st_atim.tv_sec,
        .st_atime_nsec = stat->st_atim.tv_nsec,
        .st_mtime = stat->st_mtim.tv_sec,
        .st_mtime_nsec = stat->st_mtim.tv_nsec,
        .st_ctime = stat->st_ctim.tv_sec,
        .st_ctime_nsec = stat->st_ctim.tv_nsec,
    };
    if (copy_to_user(user_buf, &stat64, sizeof(struct linux_stat64)))
        return -EFAULT;
    return 0;
}

int sys_stat64(const char* user_pathname, struct linux_stat64* user_buf) {
    struct kstat buf;
    int rc = stat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user64(&buf, user_buf);
}

int sys_lstat64(const char* user_pathname, struct linux_stat64* user_buf) {
    struct kstat buf;
    int rc = lstat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user64(&buf, user_buf);
}

int sys_fstat64(int fd, struct linux_stat64* user_buf) {
    struct kstat buf;
    int rc = fstat(fd, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user64(&buf, user_buf);
}
