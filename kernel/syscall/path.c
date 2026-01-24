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

NODISCARD
static struct inode* resolve_inode_at(int dirfd, const char* user_pathname,
                                      int flags) {
    if (flags & ~(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH))
        return ERR_PTR(-EINVAL);

    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return ERR_PTR(len);

    if (pathname[0]) {
        struct path* base FREE(path) = path_from_dirfd(dirfd);
        if (IS_ERR(ASSERT(base)))
            return ERR_PTR(PTR_ERR(base));

        int vfs_flags = 0;
        if (!(flags & AT_SYMLINK_FOLLOW))
            vfs_flags |= O_NOFOLLOW | O_NOFOLLOW_NOERROR;
        struct path* path FREE(path) =
            vfs_resolve_path_at(base, pathname, vfs_flags);
        if (IS_ERR(ASSERT(path)))
            return ERR_PTR(PTR_ERR(path));

        return inode_ref(path->inode);
    }

    if (!(flags & AT_EMPTY_PATH))
        return ERR_PTR(-ENOENT);

    struct file* file FREE(file) = files_ref_file(current->files, dirfd);
    if (IS_ERR(ASSERT(file)))
        return ERR_PTR(PTR_ERR(file));

    return inode_ref(file->inode);
}

NODISCARD static long open(const struct path* base, const char* user_pathname,
                           int flags, unsigned mode) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct file* file FREE(file) =
        vfs_open_at(base, pathname, flags & ~O_KERNEL_INTERNAL_MASK,
                    (mode & ALLPERMS) | S_IFREG);
    if (PTR_ERR(file) == -EINTR)
        return -ERESTARTSYS;
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    int fd_flags = 0;
    if (flags & O_CLOEXEC)
        fd_flags |= FD_CLOEXEC;
    return files_alloc_fd(current->files, 0, file, fd_flags);
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
        vfs_create_at(base, pathname, (mode & ALLPERMS) | S_IFDIR);
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
    struct inode* old_inode FREE(inode) =
        resolve_inode_at(olddirfd, user_oldpath, flags);
    if (IS_ERR(ASSERT(old_inode)))
        return PTR_ERR(old_inode);

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
    char target[SYMLINK_MAX + 1];
    ssize_t target_len =
        strncpy_from_user(target, user_target, SYMLINK_MAX + 1);
    if (IS_ERR(target_len))
        return target_len;
    if (target_len > SYMLINK_MAX)
        return -ENAMETOOLONG;

    char linkpath[PATH_MAX];
    ssize_t linkpath_len = copy_pathname_from_user(linkpath, user_linkpath);
    if (IS_ERR(linkpath_len))
        return linkpath_len;

    struct file* file FREE(file) =
        vfs_open_at(base, linkpath, O_CREAT | O_EXCL | O_WRONLY, S_IFLNK);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    return file_symlink(file, target, target_len);
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

static void chmod(struct inode* inode, mode_t mode) {
    SCOPED_LOCK(inode, inode);
    inode->mode = (inode->mode & ~ALLPERMS) | (mode & ALLPERMS);
}

long sys_chmod(const char* user_pathname, mode_t mode) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    SCOPED_LOCK(fs, current->fs);
    struct path* path FREE(path) =
        vfs_resolve_path_at(current->fs->cwd, pathname, 0);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);

    chmod(path->inode, mode);
    return 0;
}

long sys_fchmod(int fd, mode_t mode) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    chmod(file->inode, mode);
    return 0;
}

long sys_fchmodat(int dirfd, const char* user_pathname, mode_t mode) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct path* base FREE(path) = path_from_dirfd(dirfd);
    if (IS_ERR(ASSERT(base)))
        return PTR_ERR(base);

    struct path* path FREE(path) = vfs_resolve_path_at(base, pathname, 0);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);

    chmod(path->inode, mode);
    return 0;
}

static void chown(struct inode* inode, uid_t owner, gid_t group) {
    SCOPED_LOCK(inode, inode);

    if (owner != (uid_t)-1)
        inode->uid = owner;
    if (group != (gid_t)-1)
        inode->gid = group;

    if (S_ISDIR(inode->mode))
        return;
    // S_ISUID and S_ISGID are cleared on chown, regardless of whether
    // the owner/group actually change.
    inode->mode &= ~S_ISUID;
    if (inode->mode & S_IXGRP) {
        inode->mode &= ~S_ISGID;
    } else {
        // When S_IXGRP is not set, S_ISGID indicates mandatory locking.
    }
}

long sys_chown(const char* user_pathname, uid_t owner, gid_t group) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct path* path FREE(path) = vfs_resolve_path(pathname, 0);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);

    chown(path->inode, owner, group);
    return 0;
}

long sys_chown16(const char* user_pathname, linux_old_uid_t owner,
                 linux_old_gid_t group) {
    return sys_chown(user_pathname, owner, group);
}

long sys_lchown(const char* user_pathname, uid_t owner, gid_t group) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct path* path FREE(path) =
        vfs_resolve_path(pathname, O_NOFOLLOW | O_NOFOLLOW_NOERROR);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);

    chown(path->inode, owner, group);
    return 0;
}

long sys_lchown16(const char* user_pathname, linux_old_uid_t owner,
                  linux_old_gid_t group) {
    return sys_lchown(user_pathname, owner, group);
}

long sys_fchown(int fd, uid_t owner, gid_t group) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    chown(file->inode, owner, group);
    return 0;
}

long sys_fchown16(int fd, linux_old_uid_t owner, linux_old_gid_t group) {
    return sys_fchown(fd, owner, group);
}

long sys_fchownat(int dirfd, const char* user_pathname, uid_t owner,
                  gid_t group, int flags) {
    struct inode* inode FREE(inode) =
        resolve_inode_at(dirfd, user_pathname, flags);
    if (IS_ERR(ASSERT(inode)))
        return PTR_ERR(inode);
    chown(inode, owner, group);
    return 0;
}
