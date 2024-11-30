#include "syscall.h"
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/uio.h>
#include <kernel/api/unistd.h>
#include <kernel/fs/fs.h>
#include <kernel/fs/path.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/task.h>

NODISCARD static int copy_pathname_from_user(char* dest, const char* user_src) {
    ssize_t pathname_len = strncpy_from_user(dest, user_src, PATH_MAX);
    if (IS_ERR(pathname_len))
        return pathname_len;
    if (pathname_len >= PATH_MAX)
        return -ENAMETOOLONG;
    return 0;
}

int sys_access(const char* user_pathname, int mode) {
    (void)mode; // File permissions are not implemented in this system.

    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;
    struct path* path = vfs_resolve_path(pathname, 0);
    if (IS_ERR(path))
        return PTR_ERR(path);
    path_destroy_recursive(path);
    return 0;
}

int sys_open(const char* user_pathname, int flags, unsigned mode) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    struct file* file = vfs_open(pathname, flags, (mode & 0777) | S_IFREG);
    if (PTR_ERR(file) == -EINTR)
        return -ERESTARTSYS;
    if (IS_ERR(file))
        return PTR_ERR(file);
    rc = task_alloc_file_descriptor(-1, file);
    if (IS_ERR(rc))
        file_unref(file);
    return rc;
}

int sys_creat(const char* user_pathname, mode_t mode) {
    return sys_open(user_pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

int sys_close(int fd) {
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    file_unref(file);
    return task_free_file_descriptor(fd);
}

ssize_t sys_read(int fd, void* user_buf, size_t count) {
    if (!user_buf || !is_user_range(user_buf, count))
        return -EFAULT;
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    int rc = file_read(file, user_buf, count);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

ssize_t sys_ia32_pread64(int fd, void* user_buf, size_t count, uint32_t pos_lo,
                         uint32_t pos_hi) {
    if (!user_buf || !is_user_range(user_buf, count))
        return -EFAULT;
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    uint64_t pos = ((uint64_t)pos_hi << 32) | pos_lo;
    int rc = file_pread(file, user_buf, count, pos);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

ssize_t sys_readv(int fd, const struct iovec* user_iov, int iovcnt) {
    if (!user_iov || !is_user_range(user_iov, iovcnt * sizeof(struct iovec)))
        return -EFAULT;
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    mutex_lock(&file->offset_lock);
    ssize_t ret = 0;
    for (int i = 0; i < iovcnt; ++i) {
        struct iovec iov;
        if (copy_from_user(&iov, user_iov + i, sizeof(struct iovec))) {
            ret = -EFAULT;
            break;
        }
        if (!is_user_range(iov.iov_base, iov.iov_len)) {
            ret = -EFAULT;
            break;
        }
        ssize_t nread = file_read_to_end(file, iov.iov_base, iov.iov_len);
        if (nread == -EINTR) {
            if (ret == 0)
                ret = -ERESTARTSYS;
            break;
        }
        if (IS_ERR(nread)) {
            ret = nread;
            break;
        }
        ret += nread;
    }
    mutex_unlock(&file->offset_lock);
    return ret;
}

ssize_t sys_readlink(const char* user_pathname, char* user_buf, size_t bufsiz) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    struct path* path =
        vfs_resolve_path(pathname, O_NOFOLLOW | O_NOFOLLOW_NOERROR);
    if (IS_ERR(path))
        return PTR_ERR(path);

    struct inode* inode = path_into_inode(path);
    if (!S_ISLNK(inode->mode)) {
        inode_unref(inode);
        return -EINVAL;
    }

    struct file* file = inode_open(inode, O_RDONLY, 0);
    if (IS_ERR(file))
        return PTR_ERR(file);

    bufsiz = MIN(bufsiz, SYMLINK_MAX);

    char buf[SYMLINK_MAX];
    ssize_t nread = file_read_to_end(file, buf, bufsiz);
    file_unref(file);
    if (IS_ERR(nread))
        return nread;

    if (copy_to_user(user_buf, buf, nread))
        return -EFAULT;
    return nread;
}

ssize_t sys_write(int fd, const void* user_buf, size_t count) {
    if (!user_buf || !is_user_range(user_buf, count))
        return -EFAULT;
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    int rc = file_write(file, user_buf, count);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

ssize_t sys_ia32_pwrite64(int fd, const void* buf, size_t count,
                          uint32_t pos_lo, uint32_t pos_hi) {
    if (!buf || !is_user_range(buf, count))
        return -EFAULT;
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    uint64_t pos = ((uint64_t)pos_hi << 32) | pos_lo;
    int rc = file_pwrite(file, buf, count, pos);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

ssize_t sys_writev(int fd, const struct iovec* user_iov, int iovcnt) {
    if (!user_iov || !is_user_range(user_iov, iovcnt * sizeof(struct iovec)))
        return -EFAULT;
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    mutex_lock(&file->offset_lock);
    ssize_t ret = 0;
    for (int i = 0; i < iovcnt; ++i) {
        struct iovec iov;
        if (copy_from_user(&iov, user_iov + i, sizeof(struct iovec))) {
            ret = -EFAULT;
            break;
        }
        if (!is_user_range(iov.iov_base, iov.iov_len)) {
            ret = -EFAULT;
            break;
        }
        ssize_t nwritten = file_write_all(file, iov.iov_base, iov.iov_len);
        if (nwritten == -EINTR) {
            if (ret == 0)
                ret = -ERESTARTSYS;
            break;
        }
        if (IS_ERR(nwritten)) {
            ret = nwritten;
            break;
        }
        ret += nwritten;
    }
    mutex_unlock(&file->offset_lock);
    return ret;
}

NODISCARD static int truncate(const char* user_path, uint64_t length) {
    char path[PATH_MAX];
    int rc = copy_pathname_from_user(path, user_path);
    if (IS_ERR(rc))
        return rc;
    struct file* file = vfs_open(path, O_WRONLY, 0);
    if (IS_ERR(file))
        return PTR_ERR(file);
    rc = file_truncate(file, length);
    file_unref(file);
    return rc;
}

NODISCARD static int ftruncate(int fd, uint64_t length) {
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    return file_truncate(file, length);
}

int sys_truncate(const char* user_path, off_t length) {
    return truncate(user_path, length);
}

int sys_ftruncate(int fd, off_t length) { return ftruncate(fd, length); }

int sys_ia32_truncate64(const char* user_path, unsigned long offset_low,
                        unsigned long offset_high) {
    return truncate(user_path, ((uint64_t)offset_high << 32) | offset_low);
}

int sys_ia32_ftruncate64(int fd, unsigned long offset_low,
                         unsigned long offset_high) {
    return ftruncate(fd, ((uint64_t)offset_high << 32) | offset_low);
}

off_t sys_lseek(int fd, off_t offset, int whence) {
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    return file_seek(file, offset, whence);
}

int sys_llseek(unsigned int fd, unsigned long offset_high,
               unsigned long offset_low, loff_t* user_result,
               unsigned int whence) {
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    loff_t offset = ((loff_t)offset_high << 32) | offset_low;
    loff_t rc = file_seek(file, offset, whence);
    if (IS_ERR(rc))
        return (int)rc;
    if (copy_to_user(user_result, &rc, sizeof(rc)))
        return -EFAULT;
    return 0;
}

NODISCARD static int stat(const char* user_pathname, struct kstat* buf) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;
    rc = vfs_stat(pathname, buf, 0);
    if (IS_ERR(rc))
        return rc;
    return 0;
}

NODISCARD static int lstat(const char* user_pathname, struct kstat* buf) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;
    rc = vfs_stat(pathname, buf, O_NOFOLLOW | O_NOFOLLOW_NOERROR);
    if (IS_ERR(rc))
        return rc;
    return 0;
}

NODISCARD static int fstat(int fd, struct kstat* buf) {
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    inode_ref(file->inode);
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

int sys_symlink(const char* user_target, const char* user_linkpath) {
    char target[PATH_MAX];
    int rc = copy_pathname_from_user(target, user_target);
    if (IS_ERR(rc))
        return rc;
    size_t target_len = strlen(target);
    if (target_len > SYMLINK_MAX)
        return -ENAMETOOLONG;

    char linkpath[PATH_MAX];
    rc = copy_pathname_from_user(linkpath, user_linkpath);
    if (IS_ERR(rc))
        return rc;

    struct file* file =
        vfs_open(linkpath, O_CREAT | O_EXCL | O_WRONLY, S_IFLNK);
    if (IS_ERR(file))
        return PTR_ERR(file);
    rc = file_write_all(file, target, target_len);
    file_unref(file);
    if (IS_ERR(rc))
        return rc;
    return 0;
}

int sys_ioctl(int fd, int request, void* user_argp) {
    if (!is_user_address(user_argp))
        return -EFAULT;
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    int rc = file_ioctl(file, request, user_argp);
    if (rc == -EINTR)
        return -ERESTARTSYS;
    return rc;
}

int sys_mkdir(const char* user_pathname, mode_t mode) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;
    struct inode* inode = vfs_create(pathname, (mode & 0777) | S_IFDIR);
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    inode_unref(inode);
    return 0;
}

int sys_mknod(const char* user_pathname, mode_t mode, dev_t dev) {
    switch (mode & S_IFMT) {
    case S_IFREG:
    case S_IFCHR:
    case S_IFBLK:
    case S_IFIFO:
    case S_IFSOCK:
        break;
    default:
        return -EINVAL;
    }

    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    struct inode* inode = vfs_create(pathname, mode);
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    inode->rdev = dev;
    inode_unref(inode);
    return 0;
}

int sys_mount(const char* user_source, const char* user_target,
              const char* user_filesystemtype, unsigned long mountflags,
              const void* data) {
    (void)mountflags;
    (void)data;

    char source[PATH_MAX];
    int rc = copy_pathname_from_user(source, user_source);
    if (IS_ERR(rc))
        return rc;

    char target[PATH_MAX];
    rc = copy_pathname_from_user(target, user_target);
    if (IS_ERR(rc))
        return rc;

    char fs_type[SIZEOF_FIELD(struct file_system, name)];
    ssize_t fs_type_len =
        strncpy_from_user(fs_type, user_filesystemtype, sizeof(fs_type));
    if (IS_ERR(fs_type_len))
        return fs_type_len;
    if ((size_t)fs_type_len >= sizeof(fs_type)) {
        // There is no file system type with such a long name.
        return -ENODEV;
    }

    return vfs_mount(source, target, fs_type);
}

int sys_link(const char* user_oldpath, const char* user_newpath) {
    char old_pathname[PATH_MAX];
    int rc = copy_pathname_from_user(old_pathname, user_oldpath);
    if (IS_ERR(rc))
        return rc;
    char new_pathname[PATH_MAX];
    rc = copy_pathname_from_user(new_pathname, user_newpath);
    if (IS_ERR(rc))
        return rc;

    struct path* old_path = vfs_resolve_path(old_pathname, 0);
    if (IS_ERR(old_path))
        return PTR_ERR(old_path);
    if (S_ISDIR(old_path->inode->mode)) {
        path_destroy_recursive(old_path);
        return -EPERM;
    }

    struct path* new_path = vfs_resolve_path(new_pathname, O_ALLOW_NOENT);
    if (IS_ERR(new_path)) {
        path_destroy_recursive(old_path);
        return PTR_ERR(new_path);
    }
    if (new_path->inode) {
        rc = -EEXIST;
        goto done;
    }
    if (!new_path->parent) {
        rc = -EPERM;
        goto done;
    }

    inode_ref(new_path->parent->inode);
    inode_ref(old_path->inode);
    rc = inode_link_child(new_path->parent->inode, new_path->basename,
                          old_path->inode);

done:
    path_destroy_recursive(new_path);
    path_destroy_recursive(old_path);
    return rc;
}

int sys_unlink(const char* user_pathname) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    struct path* path = vfs_resolve_path(pathname, 0);
    if (IS_ERR(path))
        return PTR_ERR(path);
    if (!path->parent || S_ISDIR(path->inode->mode)) {
        path_destroy_recursive(path);
        return -EPERM;
    }

    inode_ref(path->parent->inode);
    rc = inode_unlink_child(path->parent->inode, path->basename);
    path_destroy_recursive(path);
    return rc;
}

static bool set_has_children(const char* name, uint8_t type, void* ctx) {
    (void)name;
    (void)type;
    *(bool*)ctx = true;
    return false;
}

static int ensure_empty_directory(struct inode* inode) {
    ASSERT(S_ISDIR(inode->mode));

    struct file* file = inode_open(inode, O_RDONLY, 0);
    if (IS_ERR(file))
        return PTR_ERR(file);

    bool has_children = false;
    int rc = file_getdents(file, set_has_children, &has_children);
    file_unref(file);
    if (IS_ERR(rc))
        return rc;

    return has_children ? -ENOTEMPTY : 0;
}

int sys_rename(const char* user_oldpath, const char* user_newpath) {
    char old_pathname[PATH_MAX];
    int rc = copy_pathname_from_user(old_pathname, user_oldpath);
    if (IS_ERR(rc))
        return rc;
    char new_pathname[PATH_MAX];
    rc = copy_pathname_from_user(new_pathname, user_newpath);
    if (IS_ERR(rc))
        return rc;

    struct path* old_path = vfs_resolve_path(old_pathname, 0);
    if (IS_ERR(old_path))
        return PTR_ERR(old_path);
    if (!old_path->parent) {
        path_destroy_recursive(old_path);
        return -EPERM;
    }

    struct path* new_path = vfs_resolve_path(new_pathname, O_ALLOW_NOENT);
    if (IS_ERR(new_path)) {
        path_destroy_recursive(old_path);
        return PTR_ERR(new_path);
    }
    if (!new_path->parent) {
        rc = -EPERM;
        goto done;
    }

    if (new_path->inode) {
        if (new_path->inode == old_path->inode)
            goto done;

        if (S_ISDIR(new_path->inode->mode)) {
            if (!S_ISDIR(old_path->inode->mode)) {
                rc = -EISDIR;
                goto done;
            }
            inode_ref(new_path->inode);
            rc = ensure_empty_directory(new_path->inode);
            if (IS_ERR(rc))
                goto done;
        }

        inode_ref(new_path->parent->inode);
        rc = inode_unlink_child(new_path->parent->inode, new_path->basename);
        if (IS_ERR(rc))
            goto done;
    }

    inode_ref(new_path->parent->inode);
    inode_ref(old_path->inode);
    rc = inode_link_child(new_path->parent->inode, new_path->basename,
                          old_path->inode);
    if (IS_ERR(rc))
        goto done;

    inode_ref(old_path->parent->inode);
    rc = inode_unlink_child(old_path->parent->inode, old_path->basename);

done:
    path_destroy_recursive(new_path);
    path_destroy_recursive(old_path);
    return rc;
}

int sys_rmdir(const char* user_pathname) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    struct path* path = vfs_resolve_path(pathname, 0);
    if (IS_ERR(path))
        return PTR_ERR(path);
    if (!path->parent) {
        path_destroy_recursive(path);
        return -EPERM;
    }
    if (!S_ISDIR(path->inode->mode)) {
        path_destroy_recursive(path);
        return -ENOTDIR;
    }
    inode_ref(path->inode);
    rc = ensure_empty_directory(path->inode);
    if (IS_ERR(rc)) {
        path_destroy_recursive(path);
        return rc;
    }
    inode_ref(path->parent->inode);
    rc = inode_unlink_child(path->parent->inode, path->basename);
    path_destroy_recursive(path);
    return rc;
}

typedef ssize_t (*fill_dir_fn)(void* user_buf, size_t buf_size,
                               const char* name, uint8_t type);

struct fill_dir_ctx {
    fill_dir_fn fill_dir;
    unsigned char* user_buf;
    size_t nremaining;
    size_t nwritten;
    int rc;
};

static bool getdents_callback(const char* name, uint8_t type, void* raw_ctx) {
    struct fill_dir_ctx* ctx = (struct fill_dir_ctx*)raw_ctx;
    ssize_t nwritten =
        ctx->fill_dir(ctx->user_buf, ctx->nremaining, name, type);
    if (IS_ERR(nwritten)) {
        ctx->rc = nwritten;
        return false;
    }
    if (nwritten == 0) {
        if (ctx->nwritten == 0)
            ctx->rc = -EINVAL;
        return false;
    }
    ASSERT((size_t)nwritten <= ctx->nremaining);
    ctx->user_buf += nwritten;
    ctx->nremaining -= nwritten;
    ctx->nwritten += nwritten;
    return true;
}

NODISCARD static ssize_t getdents(int fd, void* user_buf, size_t count,
                                  fill_dir_fn fill_dir) {
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);

    struct fill_dir_ctx ctx = {
        .fill_dir = fill_dir,
        .user_buf = user_buf,
        .nremaining = count,
    };
    int rc = file_getdents(file, getdents_callback, &ctx);
    if (IS_ERR(rc))
        return rc;
    if (IS_ERR(ctx.rc))
        return ctx.rc;
    return ctx.nwritten;
}

static ssize_t fill_dir_old(void* user_buf, size_t buf_size, const char* name,
                            uint8_t type) {
    (void)type;

    size_t name_len = strlen(name);
    size_t name_size = name_len + 1;
    size_t rec_len = offsetof(struct linux_old_dirent, d_name) //
                     + name_size;                              // d_name
    rec_len = ROUND_UP(rec_len, alignof(struct linux_old_dirent));
    if (buf_size < rec_len)
        return 0;

    struct linux_old_dirent* user_dent = user_buf;
    struct linux_old_dirent dent = {.d_namlen = name_len};
    if (copy_to_user(user_dent, &dent,
                     offsetof(struct linux_old_dirent, d_name)))
        return -EFAULT;
    if (copy_to_user(user_dent->d_name, name, name_size))
        return -EFAULT;

    return rec_len;
}

ssize_t sys_readdir(int fd, struct linux_old_dirent* user_dirp, size_t count) {
    return getdents(fd, user_dirp, count, fill_dir_old);
}

static ssize_t fill_dir(void* user_buf, size_t buf_size, const char* name,
                        uint8_t type) {
    size_t name_size = strlen(name) + 1;
    size_t rec_len = offsetof(struct linux_dirent, d_name) //
                     + name_size                           // d_name
                     + sizeof(char)                        // pad
                     + sizeof(char);                       // d_type
    rec_len = ROUND_UP(rec_len, alignof(struct linux_dirent));
    if (buf_size < rec_len)
        return 0;

    struct linux_dirent* user_dent = user_buf;
    struct linux_dirent dent = {.d_reclen = rec_len};
    if (copy_to_user(user_dent, &dent, offsetof(struct linux_dirent, d_name)))
        return -EFAULT;
    if (copy_to_user(user_dent->d_name, name, name_size))
        return -EFAULT;
    if (copy_to_user(user_dent->d_name + name_size + sizeof(char), &type,
                     sizeof(char)))
        return -EFAULT;

    return rec_len;
}

ssize_t sys_getdents(int fd, struct linux_dirent* user_dirp, size_t count) {
    return getdents(fd, user_dirp, count, fill_dir);
}

static ssize_t fill_dir64(void* user_buf, size_t buf_size, const char* name,
                          uint8_t type) {
    size_t name_size = strlen(name) + 1;
    size_t rec_len = offsetof(struct linux_dirent64, d_name) //
                     + name_size;                            // d_name
    rec_len = ROUND_UP(rec_len, alignof(struct linux_dirent64));
    if (buf_size < rec_len)
        return 0;

    struct linux_dirent64* user_dent = user_buf;
    struct linux_dirent64 dent = {
        .d_reclen = rec_len,
        .d_type = type,
    };
    if (copy_to_user(user_dent, &dent, offsetof(struct linux_dirent64, d_name)))
        return -EFAULT;
    if (copy_to_user(user_dent->d_name, name, name_size))
        return -EFAULT;

    return rec_len;
}

ssize_t sys_getdents64(int fd, struct linux_dirent* user_dirp, size_t count) {
    return getdents(fd, user_dirp, count, fill_dir64);
}

int sys_fcntl(int fd, int cmd, unsigned long arg) {
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    switch (cmd) {
    case F_DUPFD: {
        int ret = task_alloc_file_descriptor(-1, file);
        if (IS_ERR(ret))
            return ret;
        file_ref(file);
        return ret;
    }
    case F_GETFL:
        return file->flags;
    case F_SETFL:
        file->flags = arg;
        return 0;
    default:
        return -EINVAL;
    }
}

int sys_fcntl64(int fd, int cmd, unsigned long arg) {
    return sys_fcntl(fd, cmd, arg);
}

int sys_dup(int oldfd) {
    struct file* file = task_get_file(oldfd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    int new_fd = task_alloc_file_descriptor(-1, file);
    if (IS_ERR(new_fd))
        return new_fd;
    file_ref(file);
    return new_fd;
}

int sys_dup2(int oldfd, int newfd) { return sys_dup3(oldfd, newfd, 0); }

int sys_dup3(int oldfd, int newfd, int flags) {
    (void)flags;

    struct file* oldfd_file = task_get_file(oldfd);
    if (IS_ERR(oldfd_file))
        return PTR_ERR(oldfd_file);
    if (oldfd == newfd)
        return oldfd;
    struct file* newfd_file = task_get_file(newfd);
    if (IS_OK(newfd_file)) {
        file_unref(newfd_file);
        int rc = task_free_file_descriptor(newfd);
        if (IS_ERR(rc))
            return rc;
    }
    int ret = task_alloc_file_descriptor(newfd, oldfd_file);
    if (IS_ERR(ret))
        return ret;
    file_ref(oldfd_file);
    return ret;
}

int sys_pipe(int user_pipefd[2]) { return sys_pipe2(user_pipefd, 0); }

int sys_pipe2(int user_pipefd[2], int flags) {
    struct inode* fifo = fifo_create();
    if (IS_ERR(fifo))
        return PTR_ERR(fifo);

    inode_ref(fifo);
    struct file* reader_file = inode_open(fifo, O_RDONLY, flags);
    if (IS_ERR(reader_file)) {
        inode_unref(fifo);
        return PTR_ERR(reader_file);
    }

    struct file* writer_file = inode_open(fifo, O_WRONLY, flags);
    if (IS_ERR(writer_file)) {
        file_unref(reader_file);
        return PTR_ERR(writer_file);
    }

    int rc = 0;
    int writer_fd = -1;

    int reader_fd = task_alloc_file_descriptor(-1, reader_file);
    if (IS_ERR(reader_fd)) {
        rc = reader_fd;
        goto fail;
    }

    writer_fd = task_alloc_file_descriptor(-1, writer_file);
    if (IS_ERR(writer_fd)) {
        rc = writer_fd;
        goto fail;
    }

    int fds[2] = {reader_fd, writer_fd};
    if (copy_to_user(user_pipefd, fds, sizeof(int[2]))) {
        rc = -EFAULT;
        goto fail;
    }

    ASSERT(IS_OK(rc));
    return 0;

fail:
    ASSERT(IS_ERR(rc));
    if (IS_OK(reader_fd))
        task_free_file_descriptor(reader_fd);
    if (IS_OK(writer_fd))
        task_free_file_descriptor(writer_fd);
    file_unref(reader_file);
    file_unref(writer_file);
    return rc;
}

int sys_sync(void) {
    int rc = vfs_sync();
    (void)rc;
    return 0;
}

int sys_fsync(int fd) {
    struct file* file = task_get_file(fd);
    if (IS_ERR(file))
        return PTR_ERR(file);
    return file_sync(file, 0, UINT64_MAX);
}

int sys_fdatasync(int fd) { return sys_fsync(fd); }
