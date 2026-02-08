#include "private.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/file.h>
#include <kernel/fs/path.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

NODISCARD static int stat(const char* user_pathname, struct kstat* buf) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;
    return vfs_stat(pathname, buf, 0);
}

NODISCARD static int lstat(const char* user_pathname, struct kstat* buf) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;
    return vfs_stat(pathname, buf, O_NOFOLLOW | O_NOFOLLOW_NOERROR);
}

NODISCARD static int fstat(int fd, struct kstat* buf) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
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

long sys_stat(const char* user_pathname, struct linux_old_stat* user_buf) {
    struct kstat buf;
    int rc = stat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user_old(&buf, user_buf);
}

long sys_lstat(const char* user_pathname, struct linux_old_stat* user_buf) {
    struct kstat buf;
    int rc = lstat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user_old(&buf, user_buf);
}

long sys_fstat(int fd, struct linux_old_stat* user_buf) {
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

long sys_newstat(const char* user_pathname, struct linux_stat* user_buf) {
    struct kstat buf;
    int rc = stat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user(&buf, user_buf);
}

long sys_newlstat(const char* user_pathname, struct linux_stat* user_buf) {
    struct kstat buf;
    int rc = lstat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user(&buf, user_buf);
}

long sys_newfstat(int fd, struct linux_stat* user_buf) {
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

long sys_stat64(const char* user_pathname, struct linux_stat64* user_buf) {
    struct kstat buf;
    int rc = stat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user64(&buf, user_buf);
}

long sys_lstat64(const char* user_pathname, struct linux_stat64* user_buf) {
    struct kstat buf;
    int rc = lstat(user_pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user64(&buf, user_buf);
}

long sys_fstat64(int fd, struct linux_stat64* user_buf) {
    struct kstat buf;
    int rc = fstat(fd, &buf);
    if (IS_ERR(rc))
        return rc;
    return copy_stat_to_user64(&buf, user_buf);
}

NODISCARD static int stat_at(int dirfd, const char* user_pathname,
                             struct kstat* buf, int flags) {
    if (!user_pathname) {
        if (!(flags & AT_EMPTY_PATH))
            return -EFAULT;

        struct file* file FREE(file) = files_ref_file(current->files, dirfd);
        if (IS_ERR(ASSERT(file)))
            return PTR_ERR(file);

        return inode_stat(file->inode, buf);
    }

    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    if (pathname[0]) {
        struct path* base FREE(path) = path_from_dirfd(dirfd);
        if (IS_ERR(ASSERT(base)))
            return PTR_ERR(base);

        int vfs_flags = 0;
        if (flags & AT_SYMLINK_NOFOLLOW)
            vfs_flags |= O_NOFOLLOW | O_NOFOLLOW_NOERROR;
        return vfs_stat_at(base, pathname, buf, vfs_flags);
    }

    if (!(flags & AT_EMPTY_PATH))
        return -ENOENT;

    struct file* file FREE(file) = files_ref_file(current->files, dirfd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    return inode_stat(file->inode, buf);
}

NODISCARD static int fstatat(int dirfd, const char* user_pathname,
                             struct kstat* buf, int flags) {
    if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
        return -EINVAL;
    return stat_at(dirfd, user_pathname, buf, flags);
}

long sys_fstatat64(int dirfd, const char* user_pathname,
                   struct linux_stat64* user_buf, int flags) {
    struct kstat buf;
    int rc = fstatat(dirfd, user_pathname, &buf, flags);
    if (IS_ERR(rc))
        return rc;

    return copy_stat_to_user64(&buf, user_buf);
}

long sys_newfstatat(int dirfd, const char* user_pathname,
                    struct linux_stat* user_buf, int flags) {
    struct kstat buf;
    int rc = fstatat(dirfd, user_pathname, &buf, flags);
    if (IS_ERR(rc))
        return rc;

    return copy_stat_to_user(&buf, user_buf);
}

long sys_statx(int dirfd, const char* user_pathname, int flags,
               unsigned int mask, struct statx* user_statxbuf) {
    if (mask & STATX__RESERVED)
        return -EINVAL;
    if ((flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE)
        return -EINVAL;
    if ((flags & ~AT_STATX_SYNC_TYPE) & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
        return -EINVAL;

    struct kstat buf;
    int rc = stat_at(dirfd, user_pathname, &buf, flags);
    if (IS_ERR(rc))
        return rc;

    struct statx statx = {
        .stx_mask = STATX_BASIC_STATS,
        .stx_blksize = buf.st_blksize,
        .stx_nlink = buf.st_nlink,
        .stx_uid = buf.st_uid,
        .stx_gid = buf.st_gid,
        .stx_mode = buf.st_mode,
        .stx_ino = buf.st_ino,
        .stx_size = buf.st_size,
        .stx_blocks = buf.st_blocks,
        .stx_atime = {.tv_sec = buf.st_atim.tv_sec,
                      .tv_nsec = buf.st_atim.tv_nsec},
        .stx_ctime = {.tv_sec = buf.st_ctim.tv_sec,
                      .tv_nsec = buf.st_ctim.tv_nsec},
        .stx_mtime = {.tv_sec = buf.st_mtim.tv_sec,
                      .tv_nsec = buf.st_mtim.tv_nsec},
        .stx_rdev_major = major(buf.st_rdev),
        .stx_rdev_minor = minor(buf.st_rdev),
        .stx_dev_major = major(buf.st_dev),
        .stx_dev_minor = minor(buf.st_dev),
    };

    if (copy_to_user(user_statxbuf, &statx, sizeof(struct statx)))
        return -EFAULT;

    return 0;
}
