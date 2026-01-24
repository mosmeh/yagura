#include "private.h"
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/fs/file.h>
#include <kernel/fs/path.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

struct path* path_from_dirfd(int dirfd) {
    if (dirfd == AT_FDCWD) {
        SCOPED_LOCK(fs, current->fs);
        return path_dup(current->fs->cwd);
    }
    struct file* file FREE(file) = files_ref_file(current->files, dirfd);
    if (IS_ERR(ASSERT(file)))
        return ERR_PTR(PTR_ERR(file));
    if (!S_ISDIR(file->inode->mode) || !file->path)
        return ERR_PTR(-ENOTDIR);
    return path_dup(file->path);
}

NODISCARD static long open(const struct path* base, const char* user_pathname,
                           int flags, unsigned mode) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct file* file FREE(file) =
        vfs_open_at(base, pathname, flags & ~O_KERNEL_INTERNAL_MASK,
                    (mode & 0777) | S_IFREG);
    if (PTR_ERR(file) == -EINTR)
        return -ERESTARTSYS;
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    return files_alloc_fd(current->files, -1, file);
}

long sys_open(const char* user_pathname, int flags, unsigned mode) {
    SCOPED_LOCK(fs, current->fs);
    return open(current->fs->cwd, user_pathname, flags, mode);
}

long sys_openat(int dirfd, const char* user_pathname, int flags, mode_t mode) {
    struct path* base FREE(path) = path_from_dirfd(dirfd);
    if (IS_ERR(ASSERT(base)))
        return PTR_ERR(base);
    return open(base, user_pathname, flags, mode);
}

long sys_creat(const char* user_pathname, mode_t mode) {
    return sys_open(user_pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

NODISCARD static long mknod(const struct path* base, const char* user_pathname,
                            mode_t mode, dev_t dev) {
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
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct inode* inode FREE(inode) = vfs_create_at(base, pathname, mode);
    if (IS_ERR(ASSERT(inode)))
        return PTR_ERR(inode);
    inode->rdev = dev;
    return 0;
}

long sys_mknod(const char* user_pathname, mode_t mode, dev_t dev) {
    SCOPED_LOCK(fs, current->fs);
    return mknod(current->fs->cwd, user_pathname, mode, dev);
}

long sys_mknodat(int dirfd, const char* user_pathname, mode_t mode, dev_t dev) {
    struct path* base FREE(path) = path_from_dirfd(dirfd);
    if (IS_ERR(ASSERT(base)))
        return PTR_ERR(base);
    return mknod(base, user_pathname, mode, dev);
}

NODISCARD static long mkdir(const struct path* base, const char* user_pathname,
                            mode_t mode) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;
    struct inode* inode FREE(inode) =
        vfs_create_at(base, pathname, (mode & 0777) | S_IFDIR);
    if (IS_ERR(ASSERT(inode)))
        return PTR_ERR(inode);
    return 0;
}

long sys_mkdir(const char* user_pathname, mode_t mode) {
    SCOPED_LOCK(fs, current->fs);
    return mkdir(current->fs->cwd, user_pathname, mode);
}

long sys_mkdirat(int dirfd, const char* user_pathname, mode_t mode) {
    struct path* base FREE(path) = path_from_dirfd(dirfd);
    if (IS_ERR(ASSERT(base)))
        return PTR_ERR(base);
    return mkdir(base, user_pathname, mode);
}

NODISCARD static long access(const struct path* base, const char* user_pathname,
                             int mode) {
    (void)mode; // File permissions are not implemented in this system.

    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;
    struct path* path FREE(path) = vfs_resolve_path_at(base, pathname, 0);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);
    return 0;
}

long sys_access(const char* user_pathname, int mode) {
    SCOPED_LOCK(fs, current->fs);
    return access(current->fs->cwd, user_pathname, mode);
}

long sys_faccessat(int dirfd, const char* user_pathname, int mode) {
    struct path* base FREE(path) = path_from_dirfd(dirfd);
    if (IS_ERR(ASSERT(base)))
        return PTR_ERR(base);
    return access(base, user_pathname, mode);
}

NODISCARD static long link(struct inode* old_inode, const struct path* new_base,
                           const char* user_newpath) {
    if (S_ISDIR(old_inode->mode))
        return -EPERM;

    char new_pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(new_pathname, user_newpath);
    if (IS_ERR(len))
        return len;

    struct path* new_path FREE(path) =
        vfs_resolve_path_at(new_base, new_pathname, O_ALLOW_NOENT);
    if (IS_ERR(ASSERT(new_path)))
        return PTR_ERR(new_path);
    if (new_path->inode)
        return -EEXIST;
    if (!new_path->parent)
        return -EPERM;

    return inode_link(new_path->parent->inode, new_path->basename, old_inode);
}

long sys_link(const char* user_oldpath, const char* user_newpath) {
    char old_pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(old_pathname, user_oldpath);
    if (IS_ERR(len))
        return len;

    SCOPED_LOCK(fs, current->fs);

    struct path* old_path FREE(path) = vfs_resolve_path_at(
        current->fs->cwd, old_pathname, O_NOFOLLOW | O_NOFOLLOW_NOERROR);
    if (IS_ERR(ASSERT(old_path)))
        return PTR_ERR(old_path);

    return link(old_path->inode, current->fs->cwd, user_newpath);
}

long sys_linkat(int olddirfd, const char* user_oldpath, int newdirfd,
                const char* user_newpath, int flags) {
    if (flags & ~(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH))
        return -EINVAL;

    char oldpath[PATH_MAX];
    ssize_t len = copy_pathname_from_user(oldpath, user_oldpath);
    if (IS_ERR(len))
        return len;

    struct inode* old_inode FREE(inode) = NULL;
    if (oldpath[0]) {
        struct path* old_base FREE(path) = path_from_dirfd(olddirfd);
        if (IS_ERR(ASSERT(old_base)))
            return PTR_ERR(old_base);

        int vfs_flags = 0;
        if (!(flags & AT_SYMLINK_FOLLOW))
            vfs_flags |= O_NOFOLLOW | O_NOFOLLOW_NOERROR;
        struct path* path FREE(path) =
            vfs_resolve_path_at(old_base, oldpath, vfs_flags);
        if (IS_ERR(ASSERT(path)))
            return PTR_ERR(path);

        old_inode = inode_ref(path->inode);
    } else {
        if (!(flags & AT_EMPTY_PATH))
            return -ENOENT;

        struct file* file FREE(file) = files_ref_file(current->files, olddirfd);
        if (IS_ERR(ASSERT(file)))
            return PTR_ERR(file);

        old_inode = inode_ref(file->inode);
    }

    struct path* new_base FREE(path) = path_from_dirfd(newdirfd);
    if (IS_ERR(ASSERT(new_base)))
        return PTR_ERR(new_base);

    return link(old_inode, new_base, user_newpath);
}

NODISCARD
static long unlink(const struct path* base, const char* user_pathname) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct path* path FREE(path) = vfs_resolve_path_at(base, pathname, 0);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);
    if (!path->parent)
        return -EPERM;
    if (S_ISDIR(path->inode->mode))
        return -EISDIR;

    return inode_unlink(path->parent->inode, path->basename);
}

long sys_unlink(const char* user_pathname) {
    SCOPED_LOCK(fs, current->fs);
    return unlink(current->fs->cwd, user_pathname);
}

NODISCARD
static long rmdir(const struct path* base, const char* user_pathname) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct path* path FREE(path) = vfs_resolve_path_at(base, pathname, 0);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);
    if (!path->parent)
        return -EPERM;
    if (!S_ISDIR(path->inode->mode))
        return -ENOTDIR;
    int rc = ensure_directory_is_empty(path->inode);
    if (IS_ERR(rc))
        return rc;
    return inode_unlink(path->parent->inode, path->basename);
}

long sys_unlinkat(int dirfd, const char* user_pathname, int flags) {
    if (flags & ~AT_REMOVEDIR)
        return -EINVAL;

    struct path* base FREE(path) = path_from_dirfd(dirfd);
    if (IS_ERR(ASSERT(base)))
        return PTR_ERR(base);
    return (flags & AT_REMOVEDIR) ? rmdir(base, user_pathname)
                                  : unlink(base, user_pathname);
}

long sys_rmdir(const char* user_pathname) {
    SCOPED_LOCK(fs, current->fs);
    return rmdir(current->fs->cwd, user_pathname);
}

NODISCARD
static long rename(const struct path* old_base, const char* user_oldpath,
                   const struct path* new_base, const char* user_newpath) {
    char old_pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(old_pathname, user_oldpath);
    if (IS_ERR(len))
        return len;
    char new_pathname[PATH_MAX];
    len = copy_pathname_from_user(new_pathname, user_newpath);
    if (IS_ERR(len))
        return len;

    struct path* old_path FREE(path) =
        vfs_resolve_path_at(old_base, old_pathname, 0);
    if (IS_ERR(ASSERT(old_path)))
        return PTR_ERR(old_path);
    if (!old_path->parent)
        return -EPERM;

    struct path* new_path FREE(path) =
        vfs_resolve_path_at(new_base, new_pathname, O_ALLOW_NOENT);
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
            int rc = ensure_directory_is_empty(new_path->inode);
            if (IS_ERR(rc))
                return rc;
        }

        int rc = inode_unlink(new_path->parent->inode, new_path->basename);
        if (IS_ERR(rc))
            return rc;
    }

    int rc = inode_link(new_path->parent->inode, new_path->basename,
                        old_path->inode);
    if (IS_ERR(rc))
        return rc;

    return inode_unlink(old_path->parent->inode, old_path->basename);
}

long sys_rename(const char* user_oldpath, const char* user_newpath) {
    SCOPED_LOCK(fs, current->fs);
    return rename(current->fs->cwd, user_oldpath, current->fs->cwd,
                  user_newpath);
}

long sys_renameat(int olddirfd, const char* user_oldpath, int newdirfd,
                  const char* user_newpath) {
    return sys_renameat2(olddirfd, user_oldpath, newdirfd, user_newpath, 0);
}

long sys_renameat2(int olddirfd, const char* user_oldpath, int newdirfd,
                   const char* user_newpath, unsigned int flags) {
    if (flags)
        return -EINVAL;

    struct path* old_base FREE(path) = path_from_dirfd(olddirfd);
    if (IS_ERR(ASSERT(old_base)))
        return PTR_ERR(old_base);

    struct path* new_base FREE(path) = path_from_dirfd(newdirfd);
    if (IS_ERR(ASSERT(new_base)))
        return PTR_ERR(new_base);

    return rename(old_base, user_oldpath, new_base, user_newpath);
}

NODISCARD static long symlink(const struct path* base, const char* user_target,
                              const char* user_linkpath) {
    char target[PATH_MAX];
    ssize_t len = copy_pathname_from_user(target, user_target);
    if (IS_ERR(len))
        return len;
    size_t target_len = strlen(target);
    if (target_len == 0)
        return -ENOENT;
    if (target_len > SYMLINK_MAX)
        return -ENAMETOOLONG;

    char linkpath[PATH_MAX];
    len = copy_pathname_from_user(linkpath, user_linkpath);
    if (IS_ERR(len))
        return len;

    struct file* file FREE(file) =
        vfs_open_at(base, linkpath, O_CREAT | O_EXCL | O_WRONLY, S_IFLNK);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    return file_symlink(file, target);
}

long sys_symlink(const char* user_target, const char* user_linkpath) {
    SCOPED_LOCK(fs, current->fs);
    return symlink(current->fs->cwd, user_target, user_linkpath);
}

long sys_symlinkat(const char* user_target, int newdirfd,
                   const char* user_linkpath) {
    struct path* base FREE(path) = path_from_dirfd(newdirfd);
    if (IS_ERR(ASSERT(base)))
        return PTR_ERR(base);
    return symlink(base, user_target, user_linkpath);
}

NODISCARD
static long readlink(const struct path* base, const char* user_pathname,
                     char* user_buf, size_t bufsiz) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct path* path FREE(path) =
        vfs_resolve_path_at(base, pathname, O_NOFOLLOW | O_NOFOLLOW_NOERROR);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);
    if (!S_ISLNK(path->inode->mode))
        return -EINVAL;

    struct file* file FREE(file) = inode_open(path->inode, O_RDONLY);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    char buf[SYMLINK_MAX];
    len = file_readlink(file, buf, bufsiz);
    if (IS_ERR(len))
        return len;
    if (copy_to_user(user_buf, buf, len))
        return -EFAULT;
    return len;
}

long sys_readlink(const char* user_pathname, char* user_buf, size_t bufsiz) {
    if (bufsiz == 0)
        return -EINVAL;
    SCOPED_LOCK(fs, current->fs);
    return readlink(current->fs->cwd, user_pathname, user_buf, bufsiz);
}

long sys_readlinkat(int dirfd, const char* user_pathname, char* user_buf,
                    size_t bufsiz) {
    if (bufsiz == 0)
        return -EINVAL;
    struct path* base FREE(path) = path_from_dirfd(dirfd);
    if (IS_ERR(ASSERT(base)))
        return PTR_ERR(base);
    return readlink(base, user_pathname, user_buf, bufsiz);
}
