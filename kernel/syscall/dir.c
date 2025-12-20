#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/fs/path.h>
#include <kernel/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task.h>

static bool set_has_children(const char* name, ino_t ino, unsigned char type,
                             void* ctx) {
    (void)name;
    (void)ino;
    (void)type;
    *(bool*)ctx = true;
    return false;
}

int ensure_directory_is_empty(struct inode* inode) {
    ASSERT(S_ISDIR(inode->mode));

    struct file* file FREE(file) = inode_open(inode, O_RDONLY);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);

    bool has_children = false;
    int rc = file_getdents(file, set_has_children, &has_children);
    if (IS_ERR(rc))
        return rc;

    return has_children ? -ENOTEMPTY : 0;
}

int sys_mkdir(const char* user_pathname, mode_t mode) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;
    struct inode* inode FREE(inode) =
        vfs_create(pathname, (mode & 0777) | S_IFDIR);
    if (IS_ERR(ASSERT(inode)))
        return PTR_ERR(inode);
    return 0;
}

int sys_rmdir(const char* user_pathname) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    struct path* path FREE(path) = vfs_resolve_path(pathname, 0);
    if (IS_ERR(ASSERT(path)))
        return PTR_ERR(path);
    if (!path->parent)
        return -EPERM;
    if (!S_ISDIR(path->inode->mode))
        return -ENOTDIR;
    rc = ensure_directory_is_empty(path->inode);
    if (IS_ERR(rc))
        return rc;
    return inode_unlink(path->parent->inode, path->basename);
}

typedef ssize_t (*fill_dir_fn)(void* user_buf, size_t buf_size,
                               const char* name, ino_t, unsigned char type);

struct fill_dir_ctx {
    fill_dir_fn fill_dir;
    unsigned char* user_buf;
    size_t nremaining;
    size_t nwritten;
    int rc;
};

static bool getdents_callback(const char* name, ino_t ino, unsigned char type,
                              void* raw_ctx) {
    struct fill_dir_ctx* ctx = (struct fill_dir_ctx*)raw_ctx;
    ssize_t nwritten =
        ctx->fill_dir(ctx->user_buf, ctx->nremaining, name, ino, type);
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
    struct file* file FREE(file) = task_ref_file(fd);
    if (IS_ERR(ASSERT(file)))
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
                            ino_t ino, unsigned char type) {
    (void)type;

    size_t name_len = strlen(name);
    size_t name_size = name_len + 1;
    size_t rec_len = offsetof(struct linux_old_dirent, d_name) //
                     + name_size;                              // d_name
    rec_len = ROUND_UP(rec_len, alignof(struct linux_old_dirent));
    if (buf_size < rec_len)
        return 0;

    struct linux_old_dirent* user_dent = user_buf;
    struct linux_old_dirent dent = {
        .d_ino = ino,
        .d_namlen = name_len,
    };
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
                        ino_t ino, unsigned char type) {
    size_t name_size = strlen(name) + 1;
    size_t rec_len = offsetof(struct linux_dirent, d_name) //
                     + name_size                           // d_name
                     + sizeof(char)                        // pad
                     + sizeof(char);                       // d_type
    rec_len = ROUND_UP(rec_len, alignof(struct linux_dirent));
    if (buf_size < rec_len)
        return 0;

    struct linux_dirent* user_dent = user_buf;
    struct linux_dirent dent = {
        .d_ino = ino,
        .d_reclen = rec_len,
    };
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
                          ino_t ino, unsigned char type) {
    size_t name_size = strlen(name) + 1;
    size_t rec_len = offsetof(struct linux_dirent64, d_name) //
                     + name_size;                            // d_name
    rec_len = ROUND_UP(rec_len, alignof(struct linux_dirent64));
    if (buf_size < rec_len)
        return 0;

    struct linux_dirent64* user_dent = user_buf;
    struct linux_dirent64 dent = {
        .d_ino = ino,
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
