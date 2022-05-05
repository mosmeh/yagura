#include "fs.h"
#include <kernel/api/dirent.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stdio.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/scheduler.h>
#include <string.h>

int file_descriptor_table_init(file_descriptor_table* table) {
    table->entries = kmalloc(OPEN_MAX * sizeof(file_description*));
    if (!table->entries)
        return -ENOMEM;

    for (size_t i = 0; i < OPEN_MAX; ++i)
        table->entries[i] = NULL;
    return 0;
}

int file_descriptor_table_clone_from(file_descriptor_table* to,
                                     const file_descriptor_table* from) {
    to->entries = kmalloc(OPEN_MAX * sizeof(file_description*));
    if (!to->entries)
        return -ENOMEM;

    memcpy(to->entries, from->entries, OPEN_MAX * sizeof(file_description*));

    for (size_t i = 0; i < OPEN_MAX; ++i) {
        if (from->entries[i])
            ++from->entries[i]->ref_count;
    }
    return 0;
}

struct file* fs_lookup(struct file* file, const char* name) {
    if (!file->fops->lookup || !S_ISDIR(file->mode))
        return ERR_PTR(-ENOTDIR);
    return file->fops->lookup(file, name);
}

struct file* fs_create_child(struct file* file, const char* name, mode_t mode) {
    if (!file->fops->create_child || !S_ISDIR(file->mode))
        return ERR_PTR(-ENOTDIR);
    ASSERT(mode & S_IFMT);
    return file->fops->create_child(file, name, mode);
}

file_description* fs_open(struct file* file, int flags, mode_t mode) {
    if (S_ISDIR(file->mode) && (flags & O_WRONLY))
        return ERR_PTR(-EISDIR);
    if (file->fops->open) {
        int rc = file->fops->open(file, flags, mode);
        if (IS_ERR(rc))
            return ERR_PTR(rc);
    }
    file_description* desc = kmalloc(sizeof(file_description));
    if (!desc)
        return ERR_PTR(-ENOMEM);
    desc->file = file;
    desc->offset = 0;
    desc->flags = flags;
    desc->ref_count = 1;
    return desc;
}

int fs_stat(struct file* file, struct stat* buf) {
    if (file->fops->stat)
        return file->fops->stat(file, buf);
    buf->st_rdev = file->device_id;
    buf->st_mode = file->mode;
    buf->st_size = 0;
    return 0;
}

int fs_close(file_description* desc) {
    ASSERT(desc->ref_count > 0);
    if (--desc->ref_count > 0)
        return 0;
    struct file* file = desc->file;
    if (file->fops->close)
        return file->fops->close(desc);
    return 0;
}

ssize_t fs_read(file_description* desc, void* buffer, size_t count) {
    struct file* file = desc->file;
    if (S_ISDIR(file->mode))
        return -EISDIR;
    if (!file->fops->read)
        return -EINVAL;
    if (!(desc->flags & O_RDONLY))
        return -EBADF;
    return file->fops->read(desc, buffer, count);
}

ssize_t fs_write(file_description* desc, const void* buffer, size_t count) {
    struct file* file = desc->file;
    if (S_ISDIR(file->mode))
        return -EISDIR;
    if (!file->fops->write)
        return -EINVAL;
    if (!(desc->flags & O_WRONLY))
        return -EBADF;
    return file->fops->write(desc, buffer, count);
}

uintptr_t fs_mmap(file_description* desc, uintptr_t addr, size_t length,
                  off_t offset, uint16_t page_flags) {
    struct file* file = desc->file;
    if (!file->fops->mmap)
        return -ENODEV;
    if (!(desc->flags & O_RDONLY))
        return -EACCES;
    if ((page_flags & PAGE_SHARED) && (page_flags & PAGE_WRITE) &&
        ((desc->flags & O_RDWR) != O_RDWR))
        return -EACCES;
    return file->fops->mmap(desc, addr, length, offset, page_flags);
}

int fs_truncate(file_description* desc, off_t length) {
    struct file* file = desc->file;
    if (S_ISDIR(file->mode))
        return -EISDIR;
    if (!file->fops->truncate)
        return -EROFS;
    if (!(desc->flags & O_WRONLY))
        return -EBADF;
    return file->fops->truncate(desc, length);
}

off_t fs_lseek(file_description* desc, off_t offset, int whence) {
    off_t new_offset;
    switch (whence) {
    case SEEK_SET:
        new_offset = offset;
        break;
    case SEEK_CUR:
        new_offset = desc->offset + offset;
        break;
    case SEEK_END: {
        struct stat stat;
        int rc = fs_stat(desc->file, &stat);
        if (IS_ERR(rc))
            return rc;
        new_offset = stat.st_size + offset;
        break;
    }
    default:
        return -EINVAL;
    }
    if (new_offset < 0)
        return -EINVAL;
    desc->offset = new_offset;
    return new_offset;
}

int fs_ioctl(file_description* desc, int request, void* argp) {
    struct file* file = desc->file;
    if (!file->fops->ioctl)
        return -ENOTTY;
    return file->fops->ioctl(desc, request, argp);
}

long fs_readdir(file_description* desc, void* dirp, unsigned int count) {
    struct file* file = desc->file;
    if (!file->fops->readdir || !S_ISDIR(file->mode))
        return -ENOTDIR;
    return file->fops->readdir(desc, dirp, count);
}

int fs_block(file_description* desc,
             bool (*should_unblock)(file_description*)) {
    if ((desc->flags & O_NONBLOCK) && !should_unblock(desc))
        return -EAGAIN;
    return scheduler_block(should_unblock, desc);
}

uint8_t mode_to_dirent_type(mode_t mode) {
    switch (mode & S_IFMT) {
    case S_IFDIR:
        return DT_DIR;
    case S_IFCHR:
        return DT_CHR;
    case S_IFBLK:
        return DT_BLK;
    case S_IFREG:
        return DT_REG;
    case S_IFIFO:
        return DT_FIFO;
    case S_IFLNK:
        return DT_LNK;
    case S_IFSOCK:
        return DT_SOCK;
    }
    UNREACHABLE();
}
