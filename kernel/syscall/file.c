#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stat.h>
#include <kernel/fs/fs.h>
#include <kernel/process.h>

uintptr_t sys_open(const char* pathname, int flags, unsigned mode) {
    file_description* desc = vfs_open(pathname, flags, (mode & 0777) | S_IFREG);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return process_alloc_file_descriptor(desc);
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

uintptr_t sys_ioctl(int fd, int request, void* argp) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_ioctl(desc, request, argp);
}

uintptr_t sys_mkdir(const char* pathname, mode_t mode) {
    struct file* file = vfs_create(pathname, (mode & 0777) | S_IFDIR);
    if (IS_ERR(file))
        return PTR_ERR(file);
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
    struct file* file = vfs_create(pathname, mode);
    if (IS_ERR(file))
        return PTR_ERR(file);
    file->device_id = dev;
    return 0;
}

uintptr_t sys_getdents(int fd, void* dirp, size_t count) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_readdir(desc, dirp, count);
}
