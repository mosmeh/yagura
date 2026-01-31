#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/fcntl.h>
#include <kernel/fs/file.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

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

NODISCARD static long getdents(int fd, void* user_buf, size_t count,
                               fill_dir_fn fill_dir) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
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
    size_t rec_len = __builtin_offsetof(struct linux_old_dirent, d_name) +
                     name_size; // d_name
    rec_len = ROUND_UP(rec_len, _Alignof(struct linux_old_dirent));
    if (buf_size < rec_len)
        return 0;

    struct linux_old_dirent* user_dent = user_buf;
    struct linux_old_dirent dent = {
        .d_ino = ino,
        .d_namlen = name_len,
    };
    if (copy_to_user(user_dent, &dent,
                     __builtin_offsetof(struct linux_old_dirent, d_name)))
        return -EFAULT;
    if (copy_to_user(user_dent->d_name, name, name_size))
        return -EFAULT;

    return rec_len;
}

long sys_old_readdir(int fd, struct linux_old_dirent* user_dirp, size_t count) {
    return getdents(fd, user_dirp, count, fill_dir_old);
}

static ssize_t fill_dir(void* user_buf, size_t buf_size, const char* name,
                        ino_t ino, unsigned char type) {
    size_t name_size = strlen(name) + 1;
    size_t rec_len = __builtin_offsetof(struct linux_dirent, d_name) +
                     name_size       // d_name
                     + sizeof(char)  // pad
                     + sizeof(char); // d_type
    rec_len = ROUND_UP(rec_len, _Alignof(struct linux_dirent));
    if (buf_size < rec_len)
        return 0;

    struct linux_dirent* user_dent = user_buf;
    struct linux_dirent dent = {
        .d_ino = ino,
        .d_reclen = rec_len,
    };
    if (copy_to_user(user_dent, &dent,
                     __builtin_offsetof(struct linux_dirent, d_name)))
        return -EFAULT;
    if (copy_to_user(user_dent->d_name, name, name_size))
        return -EFAULT;
    if (copy_to_user((unsigned char*)user_dent + rec_len - sizeof(char), &type,
                     sizeof(char)))
        return -EFAULT;

    return rec_len;
}

long sys_getdents(int fd, struct linux_dirent* user_dirp, size_t count) {
    return getdents(fd, user_dirp, count, fill_dir);
}

static ssize_t fill_dir64(void* user_buf, size_t buf_size, const char* name,
                          ino_t ino, unsigned char type) {
    size_t name_size = strlen(name) + 1;
    size_t rec_len = __builtin_offsetof(struct linux_dirent64, d_name) //
                     + name_size;                                      // d_name
    rec_len = ROUND_UP(rec_len, _Alignof(struct linux_dirent64));
    if (buf_size < rec_len)
        return 0;

    struct linux_dirent64* user_dent = user_buf;
    struct linux_dirent64 dent = {
        .d_ino = ino,
        .d_reclen = rec_len,
        .d_type = type,
    };
    if (copy_to_user(user_dent, &dent,
                     __builtin_offsetof(struct linux_dirent64, d_name)))
        return -EFAULT;
    if (copy_to_user(user_dent->d_name, name, name_size))
        return -EFAULT;

    return rec_len;
}

long sys_getdents64(int fd, struct linux_dirent* user_dirp, size_t count) {
    return getdents(fd, user_dirp, count, fill_dir64);
}
