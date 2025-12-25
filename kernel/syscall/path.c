#include "private.h"
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/fs/file.h>
#include <kernel/fs/path.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task.h>

int copy_pathname_from_user(char dest[static PATH_MAX], const char* user_src) {
    ssize_t pathname_len = strncpy_from_user(dest, user_src, PATH_MAX);
    if (IS_ERR(pathname_len))
        return pathname_len;
    if (pathname_len >= PATH_MAX)
        return -ENAMETOOLONG;
    return 0;
}

int sys_open(const char* user_pathname, int flags, unsigned mode) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    struct file* file FREE(file) =
        vfs_open(pathname, flags, (mode & 0777) | S_IFREG);
    if (PTR_ERR(file) == -EINTR)
        return -ERESTARTSYS;
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    return task_alloc_fd(-1, file);
}

int sys_creat(const char* user_pathname, mode_t mode) {
    return sys_open(user_pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
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

    struct inode* inode FREE(inode) = vfs_create(pathname, mode);
    if (IS_ERR(ASSERT(inode)))
        return PTR_ERR(inode);
    inode->rdev = dev;
    return 0;
}

int sys_access(const char* user_pathname, int mode) {
    (void)mode; // File permissions are not implemented in this system.

    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;
    struct path* path FREE(path) = vfs_resolve_path(pathname, 0);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);
    return 0;
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

    struct path* old_path FREE(path) = vfs_resolve_path(old_pathname, 0);
    if (IS_ERR(ASSERT(old_path)))
        return PTR_ERR(old_path);
    if (S_ISDIR(old_path->inode->mode))
        return -EPERM;

    struct path* new_path FREE(path) =
        vfs_resolve_path(new_pathname, O_ALLOW_NOENT);
    if (IS_ERR(ASSERT(new_path)))
        return PTR_ERR(new_path);
    if (new_path->inode)
        return -EEXIST;
    if (!new_path->parent)
        return -EPERM;

    return inode_link(new_path->parent->inode, new_path->basename,
                      old_path->inode);
}

int sys_unlink(const char* user_pathname) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    struct path* path FREE(path) = vfs_resolve_path(pathname, 0);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);
    if (!path->parent || S_ISDIR(path->inode->mode))
        return -EPERM;

    return inode_unlink(path->parent->inode, path->basename);
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

    struct path* old_path FREE(path) = vfs_resolve_path(old_pathname, 0);
    if (IS_ERR(ASSERT(old_path)))
        return PTR_ERR(old_path);
    if (!old_path->parent)
        return -EPERM;

    struct path* new_path FREE(path) =
        vfs_resolve_path(new_pathname, O_ALLOW_NOENT);
    if (IS_ERR(ASSERT(new_path)))
        return PTR_ERR(new_path);
    if (!new_path->parent)
        return -EPERM;

    if (new_path->inode) {
        if (new_path->inode == old_path->inode)
            return 0;

        if (S_ISDIR(new_path->inode->mode)) {
            if (!S_ISDIR(old_path->inode->mode))
                return -EISDIR;
            rc = ensure_directory_is_empty(new_path->inode);
            if (IS_ERR(rc))
                return rc;
        }

        rc = inode_unlink(new_path->parent->inode, new_path->basename);
        if (IS_ERR(rc))
            return rc;
    }

    rc = inode_link(new_path->parent->inode, new_path->basename,
                    old_path->inode);
    if (IS_ERR(rc))
        return rc;

    return inode_unlink(old_path->parent->inode, old_path->basename);
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

    struct file* file FREE(file) =
        vfs_open(linkpath, O_CREAT | O_EXCL | O_WRONLY, S_IFLNK);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    return file_symlink(file, target);
}

ssize_t sys_readlink(const char* user_pathname, char* user_buf, size_t bufsiz) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    struct path* path FREE(path) =
        vfs_resolve_path(pathname, O_NOFOLLOW | O_NOFOLLOW_NOERROR);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);
    if (!S_ISLNK(path->inode->mode))
        return -EINVAL;

    struct file* file FREE(file) = inode_open(path->inode, O_RDONLY);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    char buf[SYMLINK_MAX];
    ssize_t len = file_readlink(file, buf, bufsiz);
    if (IS_ERR(len))
        return len;
    if (copy_to_user(user_buf, buf, len))
        return -EFAULT;
    return len;
}
