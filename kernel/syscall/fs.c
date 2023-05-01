#include "syscall.h"
#include <kernel/api/dirent.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/limits.h>
#include <kernel/fs/fs.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/safe_string.h>
#include <string.h>

static int copy_pathname_from_user(char* dest, const char* user_src) {
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

    file_description* desc = vfs_open(pathname, flags, (mode & 0777) | S_IFREG);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    rc = process_alloc_file_descriptor(-1, desc);
    if (IS_ERR(rc))
        file_description_close(desc);
    return rc;
}

int sys_close(int fd) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);

    int rc = file_description_close(desc);
    if (IS_ERR(rc))
        return rc;

    return process_free_file_descriptor(fd);
}

ssize_t sys_read(int fd, void* buf, size_t count) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return file_description_read(desc, buf, count);
}

ssize_t sys_write(int fd, const void* buf, size_t count) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return file_description_write(desc, buf, count);
}

int sys_ftruncate(int fd, off_t length) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return file_description_truncate(desc, length);
}

off_t sys_lseek(int fd, off_t offset, int whence) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return file_description_seek(desc, offset, whence);
}

int sys_stat(const char* user_pathname, struct stat* user_buf) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;
    struct stat buf;
    rc = vfs_stat(pathname, &buf);
    if (IS_ERR(rc))
        return rc;
    if (!copy_to_user(user_buf, &buf, sizeof(struct stat)))
        return -EFAULT;
    return 0;
}

int sys_ioctl(int fd, int request, void* user_argp) {
    if (!is_user_address(user_argp))
        return -EFAULT;
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return file_description_ioctl(desc, request, user_argp);
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
    inode->device_id = dev;
    inode_unref(inode);
    return 0;
}

int sys_link(const char* user_oldpath, const char* user_newpath) {
    char oldpath[PATH_MAX];
    int rc = copy_pathname_from_user(oldpath, user_oldpath);
    if (IS_ERR(rc))
        return rc;
    char newpath[PATH_MAX];
    rc = copy_pathname_from_user(newpath, user_newpath);
    if (IS_ERR(rc))
        return rc;

    struct inode* old_inode = vfs_resolve_path(oldpath, NULL, NULL);
    if (IS_ERR(old_inode))
        return PTR_ERR(old_inode);
    if (S_ISDIR(old_inode->mode)) {
        inode_unref(old_inode);
        return -EPERM;
    }

    struct inode* new_parent = NULL;
    char* new_basename = NULL;
    struct inode* new_inode =
        vfs_resolve_path(newpath, &new_parent, &new_basename);
    if (IS_OK(new_inode)) {
        inode_unref(old_inode);
        inode_unref(new_parent);
        inode_unref(new_inode);
        kfree(new_basename);
        return -EEXIST;
    }
    if (IS_ERR(new_inode) && PTR_ERR(new_inode) != -ENOENT) {
        inode_unref(old_inode);
        inode_unref(new_parent);
        kfree(new_basename);
        return PTR_ERR(new_inode);
    }
    if (!new_parent) {
        inode_unref(old_inode);
        kfree(new_basename);
        return -EPERM;
    }
    ASSERT(new_basename);

    rc = inode_link_child(new_parent, new_basename, old_inode);
    kfree(new_basename);
    return rc;
}

int sys_unlink(const char* user_pathname) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    struct inode* parent = NULL;
    char* basename = NULL;
    struct inode* inode = vfs_resolve_path(pathname, &parent, &basename);
    if (IS_ERR(inode)) {
        inode_unref(parent);
        kfree(basename);
        return PTR_ERR(inode);
    }
    if (!parent || S_ISDIR(inode->mode)) {
        inode_unref(parent);
        inode_unref(inode);
        kfree(basename);
        return -EPERM;
    }
    ASSERT(basename);

    inode_unref(inode);
    rc = inode_unlink_child(parent, basename);
    kfree(basename);
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

    file_description* desc = inode_open(inode, O_RDONLY, 0);
    if (IS_ERR(desc))
        return PTR_ERR(desc);

    bool has_children = false;
    int rc = file_description_getdents(desc, set_has_children, &has_children);
    file_description_close(desc);
    if (IS_ERR(rc))
        return rc;

    return has_children ? -ENOTEMPTY : 0;
}

int sys_rename(const char* user_oldpath, const char* user_newpath) {
    char oldpath[PATH_MAX];
    int rc = copy_pathname_from_user(oldpath, user_oldpath);
    if (IS_ERR(rc))
        return rc;
    char newpath[PATH_MAX];
    rc = copy_pathname_from_user(newpath, user_newpath);
    if (IS_ERR(rc))
        return rc;

    struct inode* old_parent = NULL;
    char* old_basename = NULL;
    struct inode* old_inode = NULL;
    struct inode* new_parent = NULL;
    char* new_basename = NULL;
    struct inode* new_inode = NULL;

    old_inode = vfs_resolve_path(oldpath, &old_parent, &old_basename);
    if (IS_ERR(old_inode)) {
        rc = PTR_ERR(old_inode);
        old_inode = NULL;
        goto fail;
    }
    if (!old_parent) {
        rc = -EPERM;
        goto fail;
    }
    ASSERT(old_basename);

    new_inode = vfs_resolve_path(newpath, &new_parent, &new_basename);
    if (IS_OK(new_inode)) {
        if (new_inode == old_inode) {
            rc = 0;
            goto do_nothing;
        }
        if (S_ISDIR(new_inode->mode)) {
            if (!S_ISDIR(old_inode->mode)) {
                rc = -EISDIR;
                goto fail;
            }
            rc = ensure_empty_directory(new_inode);
            if (IS_ERR(rc)) {
                new_inode = NULL;
                goto fail;
            }
        }
        inode_ref(new_parent);
        rc = inode_unlink_child(new_parent, new_basename);
        if (IS_ERR(rc))
            goto fail;
    } else {
        if (PTR_ERR(new_inode) != -ENOENT) {
            rc = PTR_ERR(new_inode);
            new_inode = NULL;
            goto fail;
        }
        new_inode = NULL;
        if (!new_parent) {
            rc = -EPERM;
            goto fail;
        }
    }
    ASSERT(new_basename);

    rc = inode_link_child(new_parent, new_basename, old_inode);
    if (IS_ERR(rc)) {
        old_inode = NULL;
        new_parent = NULL;
        goto fail;
    }
    kfree(new_basename);

    rc = inode_unlink_child(old_parent, old_basename);
    kfree(old_basename);
    return rc;

fail:
    ASSERT(IS_ERR(rc));
do_nothing:
    inode_unref(old_parent);
    inode_unref(old_inode);
    kfree(old_basename);
    inode_unref(new_parent);
    inode_unref(new_inode);
    kfree(new_basename);
    return rc;
}

int sys_rmdir(const char* user_pathname) {
    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    struct inode* parent = NULL;
    char* basename = NULL;
    struct inode* inode = vfs_resolve_path(pathname, &parent, &basename);
    if (IS_ERR(inode)) {
        inode_unref(parent);
        kfree(basename);
        return PTR_ERR(inode);
    }
    if (!parent) {
        inode_unref(inode);
        kfree(basename);
        return -EPERM;
    }
    ASSERT(basename);
    if (!S_ISDIR(inode->mode)) {
        inode_unref(parent);
        inode_unref(inode);
        kfree(basename);
        return -ENOTDIR;
    }
    rc = ensure_empty_directory(inode);
    if (IS_ERR(rc)) {
        inode_unref(parent);
        kfree(basename);
        return rc;
    }
    rc = inode_unlink_child(parent, basename);
    kfree(basename);
    return rc;
}

struct fill_dir_ctx {
    unsigned char* user_dirp;
    unsigned remaining_count;
    long nwritten;
    int rc;
};

static bool fill_dir(const char* name, uint8_t type, void* raw_ctx) {
    struct fill_dir_ctx* ctx = (struct fill_dir_ctx*)raw_ctx;
    size_t name_len = strlen(name);
    size_t name_size = name_len + 1;
    size_t size = offsetof(struct dirent, d_name) + name_size;
    if (ctx->remaining_count < size) {
        if (ctx->nwritten == 0)
            ctx->rc = -EINVAL;
        return false;
    }

    struct dirent dent = {
        .d_reclen = size, .d_type = type, .d_namlen = name_len};
    struct dirent* user_dent = (struct dirent*)ctx->user_dirp;
    if (!copy_to_user(user_dent, &dent, sizeof(struct dirent))) {
        ctx->rc = -EFAULT;
        return false;
    }
    if (!copy_to_user(user_dent->d_name, name, name_len)) {
        ctx->rc = -EFAULT;
        return false;
    }

    ctx->user_dirp += size;
    ctx->remaining_count -= size;
    ctx->nwritten += size;
    return true;
}

long sys_getdents(int fd, void* user_dirp, size_t count) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);

    struct fill_dir_ctx ctx = {.user_dirp = user_dirp,
                               .remaining_count = count,
                               .nwritten = 0,
                               .rc = 0};
    int rc = file_description_getdents(desc, fill_dir, &ctx);
    if (IS_ERR(rc))
        return rc;
    if (IS_ERR(ctx.rc))
        return ctx.rc;
    return ctx.nwritten;
}

int sys_fcntl(int fd, int cmd, uintptr_t arg) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    switch (cmd) {
    case F_DUPFD: {
        int ret = process_alloc_file_descriptor(-1, desc);
        if (IS_ERR(ret))
            return ret;
        ++desc->ref_count;
        return ret;
    }
    case F_GETFL:
        return desc->flags;
    case F_SETFL:
        desc->flags = arg;
        return 0;
    default:
        return -EINVAL;
    }
}

int sys_dup2(int oldfd, int newfd) {
    file_description* oldfd_desc = process_get_file_description(oldfd);
    if (IS_ERR(oldfd_desc))
        return PTR_ERR(oldfd_desc);
    if (oldfd == newfd)
        return oldfd;
    file_description* newfd_desc = process_get_file_description(newfd);
    if (IS_OK(newfd_desc)) {
        int rc = file_description_close(newfd_desc);
        if (IS_ERR(rc))
            return rc;
        rc = process_free_file_descriptor(newfd);
        if (IS_ERR(rc))
            return rc;
    }
    int ret = process_alloc_file_descriptor(newfd, oldfd_desc);
    if (IS_ERR(ret))
        return ret;
    ++oldfd_desc->ref_count;
    return ret;
}

int sys_pipe(int user_fifofd[2]) {
    struct inode* fifo = fifo_create();
    if (IS_ERR(fifo))
        return PTR_ERR(fifo);

    inode_ref(fifo);
    file_description* reader_desc = inode_open(fifo, O_RDONLY, 0);
    if (IS_ERR(reader_desc)) {
        inode_unref(fifo);
        return PTR_ERR(reader_desc);
    }

    file_description* writer_desc = inode_open(fifo, O_WRONLY, 0);
    if (IS_ERR(writer_desc)) {
        file_description_close(reader_desc);
        return PTR_ERR(writer_desc);
    }

    int rc = 0;
    int writer_fd = -1;

    int reader_fd = process_alloc_file_descriptor(-1, reader_desc);
    if (IS_ERR(reader_fd)) {
        rc = reader_fd;
        goto fail;
    }

    writer_fd = process_alloc_file_descriptor(-1, writer_desc);
    if (IS_ERR(writer_fd)) {
        rc = writer_fd;
        goto fail;
    }

    int fifofd[2] = {reader_fd, writer_fd};
    if (!copy_to_user(user_fifofd, fifofd, sizeof(int[2]))) {
        rc = -EFAULT;
        goto fail;
    }

    ASSERT(IS_OK(rc));
    return 0;

fail:
    ASSERT(IS_ERR(rc));
    if (IS_OK(reader_fd))
        process_free_file_descriptor(reader_fd);
    if (IS_OK(writer_fd))
        process_free_file_descriptor(writer_fd);
    file_description_close(reader_desc);
    file_description_close(writer_desc);
    return rc;
}
