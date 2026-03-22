#include "private.h"
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/fs/file.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/path.h>
#include <kernel/fs/vfs.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

struct path* path_from_dirfd(int dirfd) {
    if (dirfd == AT_FDCWD) {
        SCOPED_LOCK(fs_env, current->fs_env);
        return path_dup(current->fs_env->cwd);
    }
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, dirfd));
    if (IS_ERR(file))
        return ERR_CAST(file);
    if (!S_ISDIR(file->inode->mode) || !file->path)
        return ERR_PTR(-ENOTDIR);
    return path_dup(file->path);
}

NODISCARD
static struct inode* resolve_inode_at(int dirfd, const char* user_pathname,
                                      int flags) {
    ASSERT(flags & (AT_SYMLINK_NOFOLLOW | AT_SYMLINK_FOLLOW));
    ASSERT(!(flags & AT_SYMLINK_NOFOLLOW) || !(flags & AT_SYMLINK_FOLLOW));
    if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_SYMLINK_FOLLOW | AT_EMPTY_PATH))
        return ERR_PTR(-EINVAL);

    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return ERR_PTR(len);

    if (pathname[0]) {
        struct path* base FREE(path) = ASSERT(path_from_dirfd(dirfd));
        if (IS_ERR(base))
            return ERR_CAST(base);

        int vfs_flags = 0;
        if (flags & AT_SYMLINK_NOFOLLOW)
            vfs_flags |= O_NOFOLLOW | O_NOFOLLOW_NOERROR;
        struct path* path FREE(path) =
            ASSERT(vfs_resolve_path(base, pathname, vfs_flags));
        if (IS_ERR(path))
            return ERR_CAST(path);

        return inode_ref(path->inode);
    }

    if (!(flags & AT_EMPTY_PATH))
        return ERR_PTR(-ENOENT);

    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, dirfd));
    if (IS_ERR(file))
        return ERR_CAST(file);

    return inode_ref(file->inode);
}

static mode_t apply_umask(mode_t mode) {
    return mode & ~current->fs_env->umask;
}

NODISCARD static int open(const struct path* base, const char* user_pathname,
                          int flags, unsigned mode) {
    flags &= ~O_KERNEL_INTERNAL_MASK;

    int fd_flags = 0;
    if (flags & O_CLOEXEC) {
        fd_flags |= FD_CLOEXEC;
        flags &= ~O_CLOEXEC;
    }

    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct file* file FREE(file) = ASSERT(vfs_open(
        base, pathname, flags, apply_umask(mode & ALLPERMS) | S_IFREG));
    if (PTR_ERR(file) == -EINTR)
        return -ERESTARTSYS;
    if (IS_ERR(file))
        return PTR_ERR(file);

    return fd_table_alloc_fd(current->fd_table, 0, file, fd_flags);
}

SYSCALL3(open, const char*, user_pathname, int, flags, unsigned, mode) {
    SCOPED_LOCK(fs_env, current->fs_env);
    return open(current->fs_env->cwd, user_pathname, flags, mode);
}

SYSCALL4(openat, int, dirfd, const char*, user_pathname, int, flags, mode_t,
         mode) {
    struct path* base FREE(path) = ASSERT(path_from_dirfd(dirfd));
    if (IS_ERR(base))
        return PTR_ERR(base);
    return open(base, user_pathname, flags, mode);
}

SYSCALL2(creat, const char*, user_pathname, mode_t, mode) {
    SCOPED_LOCK(fs_env, current->fs_env);
    return open(current->fs_env->cwd, user_pathname,
                O_CREAT | O_WRONLY | O_TRUNC, mode);
}

NODISCARD static int mknod(const struct path* base, const char* user_pathname,
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

    struct inode* inode FREE(inode) =
        ASSERT(vfs_create(base, pathname, apply_umask(mode)));
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    inode->rdev = dev;
    return 0;
}

SYSCALL3(mknod, const char*, user_pathname, mode_t, mode, dev_t, dev) {
    SCOPED_LOCK(fs_env, current->fs_env);
    return mknod(current->fs_env->cwd, user_pathname, mode, dev);
}

SYSCALL4(mknodat, int, dirfd, const char*, user_pathname, mode_t, mode, dev_t,
         dev) {
    struct path* base FREE(path) = ASSERT(path_from_dirfd(dirfd));
    if (IS_ERR(base))
        return PTR_ERR(base);
    return mknod(base, user_pathname, mode, dev);
}

NODISCARD static int mkdir(const struct path* base, const char* user_pathname,
                           mode_t mode) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;
    struct inode* inode FREE(inode) = ASSERT(
        vfs_create(base, pathname, apply_umask(mode & ALLPERMS) | S_IFDIR));
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    return 0;
}

SYSCALL2(mkdir, const char*, user_pathname, mode_t, mode) {
    SCOPED_LOCK(fs_env, current->fs_env);
    return mkdir(current->fs_env->cwd, user_pathname, mode);
}

SYSCALL3(mkdirat, int, dirfd, const char*, user_pathname, mode_t, mode) {
    struct path* base FREE(path) = ASSERT(path_from_dirfd(dirfd));
    if (IS_ERR(base))
        return PTR_ERR(base);
    return mkdir(base, user_pathname, mode);
}

NODISCARD static int access(const struct path* base, const char* user_pathname,
                            int mode) {
    (void)mode; // File permissions are not implemented in this system.

    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;
    struct path* path FREE(path) = ASSERT(vfs_resolve_path(base, pathname, 0));
    if (IS_ERR(path))
        return PTR_ERR(path);
    return 0;
}

SYSCALL2(access, const char*, user_pathname, int, mode) {
    SCOPED_LOCK(fs_env, current->fs_env);
    return access(current->fs_env->cwd, user_pathname, mode);
}

SYSCALL3(faccessat, int, dirfd, const char*, user_pathname, int, mode) {
    struct path* base FREE(path) = ASSERT(path_from_dirfd(dirfd));
    if (IS_ERR(base))
        return PTR_ERR(base);
    return access(base, user_pathname, mode);
}

NODISCARD static int link(struct inode* old_inode, const struct path* new_base,
                          const char* user_newpath) {
    if (S_ISDIR(old_inode->mode))
        return -EPERM;

    char new_pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(new_pathname, user_newpath);
    if (IS_ERR(len))
        return len;

    struct path* new_path FREE(path) = ASSERT(
        vfs_resolve_path(new_base, new_pathname,
                         O_ALLOW_NOENT | O_NOFOLLOW | O_NOFOLLOW_NOERROR));
    if (IS_ERR(new_path))
        return PTR_ERR(new_path);
    if (new_path->inode)
        return -EEXIST;
    if (!new_path->parent)
        return -EPERM;

    return inode_link(new_path->parent->inode, new_path->basename, old_inode);
}

SYSCALL2(link, const char*, user_oldpath, const char*, user_newpath) {
    char old_pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(old_pathname, user_oldpath);
    if (IS_ERR(len))
        return len;

    SCOPED_LOCK(fs_env, current->fs_env);

    struct path* old_path FREE(path) = ASSERT(vfs_resolve_path(
        current->fs_env->cwd, old_pathname, O_NOFOLLOW | O_NOFOLLOW_NOERROR));
    if (IS_ERR(old_path))
        return PTR_ERR(old_path);

    return link(old_path->inode, current->fs_env->cwd, user_newpath);
}

SYSCALL5(linkat, int, olddirfd, const char*, user_oldpath, int, newdirfd,
         const char*, user_newpath, int, flags) {
    if (flags & ~(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH))
        return -EINVAL;
    if (!(flags & AT_SYMLINK_FOLLOW))
        flags |= AT_SYMLINK_NOFOLLOW;

    struct inode* old_inode FREE(inode) =
        ASSERT(resolve_inode_at(olddirfd, user_oldpath, flags));
    if (IS_ERR(old_inode))
        return PTR_ERR(old_inode);

    struct path* new_base FREE(path) = ASSERT(path_from_dirfd(newdirfd));
    if (IS_ERR(new_base))
        return PTR_ERR(new_base);

    return link(old_inode, new_base, user_newpath);
}

NODISCARD
static int unlink(const struct path* base, const char* user_pathname) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct path* path FREE(path) = ASSERT(
        vfs_resolve_path(base, pathname, O_NOFOLLOW | O_NOFOLLOW_NOERROR));
    if (IS_ERR(path))
        return PTR_ERR(path);
    if (!path->parent)
        return -EPERM;
    if (S_ISDIR(path->inode->mode))
        return -EISDIR;

    return inode_unlink(path->parent->inode, path->basename);
}

SYSCALL1(unlink, const char*, user_pathname) {
    SCOPED_LOCK(fs_env, current->fs_env);
    return unlink(current->fs_env->cwd, user_pathname);
}

NODISCARD
static int rmdir(const struct path* base, const char* user_pathname) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct path* path FREE(path) = ASSERT(
        vfs_resolve_path(base, pathname, O_NOFOLLOW | O_NOFOLLOW_NOERROR));
    if (IS_ERR(path))
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

SYSCALL3(unlinkat, int, dirfd, const char*, user_pathname, int, flags) {
    if (flags & ~AT_REMOVEDIR)
        return -EINVAL;

    struct path* base FREE(path) = ASSERT(path_from_dirfd(dirfd));
    if (IS_ERR(base))
        return PTR_ERR(base);
    return (flags & AT_REMOVEDIR) ? rmdir(base, user_pathname)
                                  : unlink(base, user_pathname);
}

SYSCALL1(rmdir, const char*, user_pathname) {
    SCOPED_LOCK(fs_env, current->fs_env);
    return rmdir(current->fs_env->cwd, user_pathname);
}

NODISCARD
static int rename(const struct path* old_base, const char* user_oldpath,
                  const struct path* new_base, const char* user_newpath) {
    char old_pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(old_pathname, user_oldpath);
    if (IS_ERR(len))
        return len;
    char new_pathname[PATH_MAX];
    len = copy_pathname_from_user(new_pathname, user_newpath);
    if (IS_ERR(len))
        return len;

    struct path* old_path FREE(path) = ASSERT(vfs_resolve_path(
        old_base, old_pathname, O_NOFOLLOW | O_NOFOLLOW_NOERROR));
    if (IS_ERR(old_path))
        return PTR_ERR(old_path);
    if (!old_path->parent)
        return -EPERM;

    struct path* new_path FREE(path) = ASSERT(
        vfs_resolve_path(new_base, new_pathname,
                         O_ALLOW_NOENT | O_NOFOLLOW | O_NOFOLLOW_NOERROR));
    if (IS_ERR(new_path))
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
        } else if (S_ISDIR(old_path->inode->mode)) {
            return -ENOTDIR;
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

SYSCALL2(rename, const char*, user_oldpath, const char*, user_newpath) {
    SCOPED_LOCK(fs_env, current->fs_env);
    return rename(current->fs_env->cwd, user_oldpath, current->fs_env->cwd,
                  user_newpath);
}

NODISCARD static int renameat2(int olddirfd, const char* user_oldpath,
                               int newdirfd, const char* user_newpath,
                               unsigned int flags) {
    if (flags)
        return -EINVAL;

    struct path* old_base FREE(path) = ASSERT(path_from_dirfd(olddirfd));
    if (IS_ERR(old_base))
        return PTR_ERR(old_base);

    struct path* new_base FREE(path) = ASSERT(path_from_dirfd(newdirfd));
    if (IS_ERR(new_base))
        return PTR_ERR(new_base);

    return rename(old_base, user_oldpath, new_base, user_newpath);
}

SYSCALL4(renameat, int, olddirfd, const char*, user_oldpath, int, newdirfd,
         const char*, user_newpath) {
    return renameat2(olddirfd, user_oldpath, newdirfd, user_newpath, 0);
}

SYSCALL5(renameat2, int, olddirfd, const char*, user_oldpath, int, newdirfd,
         const char*, user_newpath, unsigned int, flags) {
    return renameat2(olddirfd, user_oldpath, newdirfd, user_newpath, flags);
}

NODISCARD static int symlink(const struct path* base, const char* user_target,
                             const char* user_linkpath) {
    char target[SYMLINK_MAX + 1];
    ssize_t target_len =
        strncpy_from_user(target, user_target, SYMLINK_MAX + 1);
    if (IS_ERR(target_len))
        return target_len;
    if (target_len == 0)
        return -ENOENT;
    if (target_len > SYMLINK_MAX)
        return -ENAMETOOLONG;

    char linkpath[PATH_MAX];
    ssize_t linkpath_len = copy_pathname_from_user(linkpath, user_linkpath);
    if (IS_ERR(linkpath_len))
        return linkpath_len;

    struct file* file FREE(file) =
        ASSERT(vfs_open(base, linkpath, O_CREAT | O_EXCL | O_WRONLY, S_IFLNK));
    if (IS_ERR(file))
        return PTR_ERR(file);

    return file_symlink(file, target, target_len);
}

SYSCALL2(symlink, const char*, user_target, const char*, user_linkpath) {
    SCOPED_LOCK(fs_env, current->fs_env);
    return symlink(current->fs_env->cwd, user_target, user_linkpath);
}

SYSCALL3(symlinkat, const char*, user_target, int, newdirfd, const char*,
         user_linkpath) {
    struct path* base FREE(path) = ASSERT(path_from_dirfd(newdirfd));
    if (IS_ERR(base))
        return PTR_ERR(base);
    return symlink(base, user_target, user_linkpath);
}

NODISCARD
static ssize_t readlink(const struct path* base, const char* user_pathname,
                        char* user_buf, size_t bufsiz) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct path* path FREE(path) = ASSERT(
        vfs_resolve_path(base, pathname, O_NOFOLLOW | O_NOFOLLOW_NOERROR));
    if (IS_ERR(path))
        return PTR_ERR(path);
    if (!S_ISLNK(path->inode->mode))
        return -EINVAL;

    struct file* file FREE(file) = ASSERT(inode_open(path->inode, O_RDONLY));
    if (IS_ERR(file))
        return PTR_ERR(file);

    char buf[SYMLINK_MAX];
    len = file_readlink(file, buf, bufsiz);
    if (IS_ERR(len))
        return len;
    if (copy_to_user(user_buf, buf, len))
        return -EFAULT;
    return len;
}

SYSCALL3(readlink, const char*, user_pathname, char*, user_buf, size_t,
         bufsiz) {
    if (bufsiz == 0)
        return -EINVAL;
    SCOPED_LOCK(fs_env, current->fs_env);
    return readlink(current->fs_env->cwd, user_pathname, user_buf, bufsiz);
}

SYSCALL4(readlinkat, int, dirfd, const char*, user_pathname, char*, user_buf,
         size_t, bufsiz) {
    if (bufsiz == 0)
        return -EINVAL;
    struct path* base FREE(path) = ASSERT(path_from_dirfd(dirfd));
    if (IS_ERR(base))
        return PTR_ERR(base);
    return readlink(base, user_pathname, user_buf, bufsiz);
}

static void chmod(struct inode* inode, mode_t mode) {
    SCOPED_LOCK(inode, inode);
    inode->mode = (inode->mode & ~ALLPERMS) | (mode & ALLPERMS);
}

SYSCALL2(chmod, const char*, user_pathname, mode_t, mode) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    SCOPED_LOCK(fs_env, current->fs_env);
    struct path* path FREE(path) =
        ASSERT(vfs_resolve_path(current->fs_env->cwd, pathname, 0));
    if (IS_ERR(path))
        return PTR_ERR(path);

    chmod(path->inode, mode);
    return 0;
}

SYSCALL2(fchmod, int, fd, mode_t, mode) {
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    chmod(file->inode, mode);
    return 0;
}

SYSCALL3(fchmodat, int, dirfd, const char*, user_pathname, mode_t, mode) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct path* base FREE(path) = ASSERT(path_from_dirfd(dirfd));
    if (IS_ERR(base))
        return PTR_ERR(base);

    struct path* path FREE(path) = ASSERT(vfs_resolve_path(base, pathname, 0));
    if (IS_ERR(path))
        return PTR_ERR(path);

    chmod(path->inode, mode);
    return 0;
}

static void chown_inode(struct inode* inode, uid_t owner, gid_t group) {
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

NODISCARD static int chown(const char* user_pathname, uid_t owner, gid_t group,
                           int flags) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    struct path* path FREE(path) =
        ASSERT(vfs_resolve_path(BASE_CWD, pathname, flags));
    if (IS_ERR(path))
        return PTR_ERR(path);

    chown_inode(path->inode, owner, group);
    return 0;
}

SYSCALL3(chown, const char*, user_pathname, uid_t, owner, gid_t, group) {
    return chown(user_pathname, owner, group, 0);
}

SYSCALL3(chown16, const char*, user_pathname, linux_old_uid_t, owner,
         linux_old_gid_t, group) {
    return chown(user_pathname, owner, group, 0);
}

SYSCALL3(lchown, const char*, user_pathname, uid_t, owner, gid_t, group) {
    return chown(user_pathname, owner, group, O_NOFOLLOW | O_NOFOLLOW_NOERROR);
}

SYSCALL3(lchown16, const char*, user_pathname, linux_old_uid_t, owner,
         linux_old_gid_t, group) {
    return chown(user_pathname, owner, group, O_NOFOLLOW | O_NOFOLLOW_NOERROR);
}

NODISCARD static int fchown(int fd, uid_t owner, gid_t group) {
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    chown_inode(file->inode, owner, group);
    return 0;
}

SYSCALL3(fchown, int, fd, uid_t, owner, gid_t, group) {
    return fchown(fd, owner, group);
}

SYSCALL3(fchown16, int, fd, linux_old_uid_t, owner, linux_old_gid_t, group) {
    return fchown(fd, owner, group);
}

SYSCALL5(fchownat, int, dirfd, const char*, user_pathname, uid_t, owner, gid_t,
         group, int, flags) {
    if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
        return -EINVAL;
    if (!(flags & AT_SYMLINK_NOFOLLOW))
        flags |= AT_SYMLINK_FOLLOW;
    struct inode* inode FREE(inode) =
        ASSERT(resolve_inode_at(dirfd, user_pathname, flags));
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    chown_inode(inode, owner, group);
    return 0;
}
