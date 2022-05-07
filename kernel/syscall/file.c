#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/stat.h>
#include <kernel/fs/fs.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/system.h>

uintptr_t sys_open(const char* pathname, int flags, unsigned mode) {
    file_description* desc = vfs_open(pathname, flags, (mode & 0777) | S_IFREG);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return process_alloc_file_descriptor(-1, desc);
}

uintptr_t sys_close(int fd) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);

    int rc = fs_close(desc);
    if (IS_ERR(rc))
        return rc;

    return process_free_file_descriptor(fd);
}

uintptr_t sys_read(int fd, void* buf, size_t count) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_read(desc, buf, count);
}

uintptr_t sys_write(int fd, const void* buf, size_t count) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_write(desc, buf, count);
}

uintptr_t sys_ftruncate(int fd, off_t length) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_truncate(desc, length);
}

uintptr_t sys_lseek(int fd, off_t offset, int whence) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_lseek(desc, offset, whence);
}

uintptr_t sys_stat(const char* pathname, struct stat* buf) {
    return vfs_stat(pathname, buf);
}

uintptr_t sys_ioctl(int fd, int request, void* argp) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_ioctl(desc, request, argp);
}

uintptr_t sys_mkdir(const char* pathname, mode_t mode) {
    struct inode* inode = vfs_create(pathname, (mode & 0777) | S_IFDIR);
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    return 0;
}

uintptr_t sys_mknod(const char* pathname, mode_t mode, dev_t dev) {
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
    struct inode* inode = vfs_create(pathname, mode);
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    inode->device_id = dev;
    return 0;
}

uintptr_t sys_link(const char* oldpath, const char* newpath) {
    struct inode* old_inode = vfs_resolve_path(oldpath, NULL, NULL);
    if (IS_ERR(old_inode))
        return PTR_ERR(old_inode);
    if (S_ISDIR(old_inode->mode))
        return -EPERM;

    struct inode* new_parent = NULL;
    const char* new_basename = NULL;
    struct inode* new_inode =
        vfs_resolve_path(newpath, &new_parent, &new_basename);
    if (IS_OK(new_inode))
        return -EEXIST;
    if (IS_ERR(new_inode) && PTR_ERR(new_inode) != -ENOENT)
        return PTR_ERR(new_inode);
    if (!new_parent)
        return -EPERM;
    ASSERT(new_basename);

    return fs_link_child(new_parent, new_basename, old_inode);
}

uintptr_t sys_unlink(const char* pathname) {
    struct inode* parent = NULL;
    const char* basename = NULL;
    struct inode* inode = vfs_resolve_path(pathname, &parent, &basename);
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    if (!parent || S_ISDIR(inode->mode))
        return -EPERM;
    ASSERT(basename);

    return fs_unlink_child(parent, basename);
}

static int make_sure_directory_is_empty(struct inode* inode) {
    ASSERT(S_ISDIR(inode->mode));

    file_description* desc = fs_open(inode, O_RDONLY, 0);
    if (IS_ERR(desc))
        return PTR_ERR(desc);

    unsigned char* buf = NULL;
    size_t capacity = 1024;
    ssize_t nread;
    for (;;) {
        buf = krealloc(buf, capacity);
        if (!buf) {
            nread = -ENOMEM;
            break;
        }
        nread = fs_readdir(desc, buf, capacity);
        if (nread != -EINVAL)
            break;
        capacity *= 2;
    }
    fs_close(desc);
    kfree(buf);

    return nread > 0 ? -ENOTEMPTY : nread;
}

uintptr_t sys_rename(const char* oldpath, const char* newpath) {
    struct inode* old_parent = NULL;
    const char* old_basename = NULL;
    struct inode* old_inode =
        vfs_resolve_path(oldpath, &old_parent, &old_basename);
    if (IS_ERR(old_inode))
        return PTR_ERR(old_inode);
    if (!old_parent)
        return -EPERM;
    ASSERT(old_basename);

    struct inode* new_parent = NULL;
    const char* new_basename = NULL;
    struct inode* new_inode =
        vfs_resolve_path(newpath, &new_parent, &new_basename);
    if (IS_OK(new_inode)) {
        if (new_inode == old_inode)
            return 0;
        if (S_ISDIR(new_inode->mode)) {
            if (!S_ISDIR(old_inode->mode))
                return -EISDIR;
            int rc = make_sure_directory_is_empty(new_inode);
            if (IS_ERR(rc))
                return rc;
        }
        int rc = fs_unlink_child(new_parent, new_basename);
        if (IS_ERR(rc))
            return rc;
    } else {
        if (PTR_ERR(new_inode) != -ENOENT)
            return PTR_ERR(new_inode);
        if (!new_parent)
            return -EPERM;
    }
    ASSERT(new_basename);

    int rc = fs_link_child(new_parent, new_basename, old_inode);
    if (IS_ERR(rc))
        return rc;
    return fs_unlink_child(old_parent, old_basename);
}

uintptr_t sys_getdents(int fd, void* dirp, size_t count) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_readdir(desc, dirp, count);
}

uintptr_t sys_fcntl(int fd, int cmd, uintptr_t arg) {
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

uintptr_t sys_dup(int oldfd) {
    file_description* desc = process_get_file_description(oldfd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    int ret = process_alloc_file_descriptor(-1, desc);
    if (IS_ERR(ret))
        return ret;
    ++desc->ref_count;
    return ret;
}

uintptr_t sys_dup2(int oldfd, int newfd) {
    file_description* oldfd_desc = process_get_file_description(oldfd);
    if (IS_ERR(oldfd_desc))
        return PTR_ERR(oldfd_desc);
    file_description* newfd_desc = process_get_file_description(newfd);
    if (IS_OK(newfd_desc)) {
        int rc = fs_close(newfd_desc);
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

uintptr_t sys_pipe(int fifofd[2]) {
    struct inode* fifo = fifo_create();

    file_description* reader_desc = fs_open(fifo, O_RDONLY, 0);
    if (IS_ERR(reader_desc))
        return PTR_ERR(reader_desc);

    file_description* writer_desc = fs_open(fifo, O_WRONLY, 0);
    if (IS_ERR(writer_desc))
        return PTR_ERR(writer_desc);

    int reader_fd = process_alloc_file_descriptor(-1, reader_desc);
    if (IS_ERR(reader_fd)) {
        fs_close(reader_desc);
        fs_close(writer_desc);
        return reader_fd;
    }

    int writer_fd = process_alloc_file_descriptor(-1, writer_desc);
    if (IS_ERR(writer_fd)) {
        fs_close(reader_desc);
        fs_close(writer_desc);
        int rc = process_free_file_descriptor(reader_fd);
        (void)rc;
        return writer_fd;
    }

    fifofd[0] = reader_fd;
    fifofd[1] = writer_fd;

    return 0;
}
