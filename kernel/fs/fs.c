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

struct inode* fs_lookup_child(struct inode* inode, const char* name) {
    if (!inode->fops->lookup_child || !S_ISDIR(inode->mode))
        return ERR_PTR(-ENOTDIR);
    return inode->fops->lookup_child(inode, name);
}

struct inode* fs_create_child(struct inode* inode, const char* name,
                              mode_t mode) {
    if (!inode->fops->create_child || !S_ISDIR(inode->mode))
        return ERR_PTR(-ENOTDIR);
    ASSERT(mode & S_IFMT);
    struct inode* child = inode->fops->create_child(inode, name, mode);
    if (IS_ERR(child))
        return child;
    child->num_links = 1;
    return child;
}

int fs_link_child(struct inode* inode, const char* name, struct inode* child) {
    if (!inode->fops->link_child || !S_ISDIR(inode->mode))
        return -ENOTDIR;
    int rc = inode->fops->link_child(inode, name, child);
    if (IS_ERR(rc))
        return rc;
    ++child->num_links;
    return 0;
}

int fs_unlink_child(struct inode* inode, const char* name) {
    if (!inode->fops->unlink_child || !S_ISDIR(inode->mode))
        return -ENOTDIR;
    struct inode* child = inode->fops->unlink_child(inode, name);
    if (IS_ERR(child))
        return PTR_ERR(child);
    ASSERT(child->num_links > 0);
    --child->num_links;
    return 0;
}

file_description* fs_open(struct inode* inode, int flags, mode_t mode) {
    if (S_ISDIR(inode->mode) && (flags & O_WRONLY))
        return ERR_PTR(-EISDIR);
    if (inode->fops->open) {
        int rc = inode->fops->open(inode, flags, mode);
        if (IS_ERR(rc))
            return ERR_PTR(rc);
    }
    file_description* desc = kmalloc(sizeof(file_description));
    if (!desc)
        return ERR_PTR(-ENOMEM);
    desc->inode = inode;
    desc->offset = 0;
    desc->flags = flags;
    desc->ref_count = 1;
    return desc;
}

int fs_stat(struct inode* inode, struct stat* buf) {
    if (inode->fops->stat)
        return inode->fops->stat(inode, buf);
    buf->st_rdev = inode->device_id;
    buf->st_mode = inode->mode;
    buf->st_size = 0;
    return 0;
}

int fs_close(file_description* desc) {
    ASSERT(desc->ref_count > 0);
    if (--desc->ref_count > 0)
        return 0;
    struct inode* inode = desc->inode;
    if (inode->fops->close)
        return inode->fops->close(desc);
    return 0;
}

ssize_t fs_read(file_description* desc, void* buffer, size_t count) {
    struct inode* inode = desc->inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;
    if (!inode->fops->read)
        return -EINVAL;
    if (!(desc->flags & O_RDONLY))
        return -EBADF;
    return inode->fops->read(desc, buffer, count);
}

ssize_t fs_write(file_description* desc, const void* buffer, size_t count) {
    struct inode* inode = desc->inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;
    if (!inode->fops->write)
        return -EINVAL;
    if (!(desc->flags & O_WRONLY))
        return -EBADF;
    return inode->fops->write(desc, buffer, count);
}

uintptr_t fs_mmap(file_description* desc, uintptr_t addr, size_t length,
                  off_t offset, uint16_t page_flags) {
    struct inode* inode = desc->inode;
    if (!inode->fops->mmap)
        return -ENODEV;
    if (!(desc->flags & O_RDONLY))
        return -EACCES;
    if ((page_flags & PAGE_SHARED) && (page_flags & PAGE_WRITE) &&
        ((desc->flags & O_RDWR) != O_RDWR))
        return -EACCES;
    return inode->fops->mmap(desc, addr, length, offset, page_flags);
}

int fs_truncate(file_description* desc, off_t length) {
    struct inode* inode = desc->inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;
    if (!inode->fops->truncate)
        return -EROFS;
    if (!(desc->flags & O_WRONLY))
        return -EBADF;
    return inode->fops->truncate(desc, length);
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
        int rc = fs_stat(desc->inode, &stat);
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
    struct inode* inode = desc->inode;
    if (!inode->fops->ioctl)
        return -ENOTTY;
    return inode->fops->ioctl(desc, request, argp);
}

long fs_readdir(file_description* desc, void* dirp, unsigned int count) {
    struct inode* inode = desc->inode;
    if (!inode->fops->readdir || !S_ISDIR(inode->mode))
        return -ENOTDIR;
    return inode->fops->readdir(desc, dirp, count);
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
