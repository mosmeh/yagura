#include "fs.h"
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stdio.h>
#include <kernel/lock.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/scheduler.h>

int file_descriptor_table_init(file_descriptor_table* table) {
    table->entries = kmalloc(OPEN_MAX * sizeof(file_description*));
    if (!table->entries)
        return -ENOMEM;

    for (size_t i = 0; i < OPEN_MAX; ++i)
        table->entries[i] = NULL;
    return 0;
}

void file_descriptor_table_destroy(file_descriptor_table* table) {
    file_description** it = table->entries;
    for (int i = 0; i < OPEN_MAX; ++i, ++it) {
        if (*it)
            file_description_close(*it);
    }
    kfree(table->entries);
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

void inode_ref(struct inode* inode) {
    ASSERT(inode);
    ++inode->ref_count;
}

void inode_unref(struct inode* inode) {
    if (!inode)
        return;
    ASSERT(inode->ref_count > 0);
    if (--inode->ref_count == 0 && inode->num_links == 0)
        inode_destroy(inode);
}

void inode_destroy(struct inode* inode) {
    ASSERT(inode->ref_count == 0 && inode->num_links == 0);
    ASSERT(inode->fops->destroy_inode);
    inode->fops->destroy_inode(inode);
}

struct inode* inode_lookup_child(struct inode* inode, const char* name) {
    if (!inode->fops->lookup_child || !S_ISDIR(inode->mode)) {
        inode_unref(inode);
        return ERR_PTR(-ENOTDIR);
    }
    return inode->fops->lookup_child(inode, name);
}

struct inode* inode_create_child(struct inode* inode, const char* name,
                                 mode_t mode) {
    if (!inode->fops->create_child || !S_ISDIR(inode->mode)) {
        inode_unref(inode);
        return ERR_PTR(-ENOTDIR);
    }
    ASSERT(mode & S_IFMT);
    return inode->fops->create_child(inode, name, mode);
}

int inode_link_child(struct inode* inode, const char* name,
                     struct inode* child) {
    if (!inode->fops->link_child || !S_ISDIR(inode->mode)) {
        inode_unref(inode);
        inode_unref(child);
        return -ENOTDIR;
    }
    if (inode->fs_root_inode != child->fs_root_inode) {
        inode_unref(inode);
        inode_unref(child);
        return -EXDEV;
    }
    return inode->fops->link_child(inode, name, child);
}

int inode_unlink_child(struct inode* inode, const char* name) {
    if (!inode->fops->unlink_child || !S_ISDIR(inode->mode)) {
        inode_unref(inode);
        return -ENOTDIR;
    }
    struct inode* child = inode->fops->unlink_child(inode, name);
    if (IS_ERR(child))
        return PTR_ERR(child);
    inode_unref(child);
    return 0;
}

file_description* inode_open(struct inode* inode, int flags, mode_t mode) {
    if (S_ISDIR(inode->mode) && (flags & O_WRONLY)) {
        inode_unref(inode);
        return ERR_PTR(-EISDIR);
    }

    file_description* desc = kmalloc(sizeof(file_description));
    if (!desc) {
        inode_unref(inode);
        return ERR_PTR(-ENOMEM);
    }
    *desc = (file_description){0};
    desc->inode = inode;
    desc->flags = flags;
    desc->ref_count = 1;

    if (inode->fops->open) {
        int rc = inode->fops->open(desc, flags, mode);
        if (IS_ERR(rc)) {
            inode_unref(inode);
            kfree(desc);
            return ERR_PTR(rc);
        }
    }
    return desc;
}

int inode_stat(struct inode* inode, struct stat* buf) {
    if (inode->fops->stat)
        return inode->fops->stat(inode, buf);
    buf->st_rdev = inode->device_id;
    buf->st_mode = inode->mode;
    buf->st_nlink = inode->num_links;
    buf->st_size = 0;
    inode_unref(inode);
    return 0;
}

int file_description_close(file_description* desc) {
    ASSERT(desc);
    ASSERT(desc->ref_count > 0);
    if (--desc->ref_count > 0)
        return 0;
    struct inode* inode = desc->inode;
    if (inode->fops->close) {
        int rc = inode->fops->close(desc);
        if (IS_ERR(rc))
            return rc;
    }
    kfree(desc);
    inode_unref(inode);
    return 0;
}

ssize_t file_description_read(file_description* desc, void* buffer,
                              size_t count) {
    struct inode* inode = desc->inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;
    if (!inode->fops->read)
        return -EINVAL;
    if (!(desc->flags & O_RDONLY))
        return -EBADF;
    return inode->fops->read(desc, buffer, count);
}

ssize_t file_description_write(file_description* desc, const void* buffer,
                               size_t count) {
    struct inode* inode = desc->inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;
    if (!inode->fops->write)
        return -EINVAL;
    if (!(desc->flags & O_WRONLY))
        return -EBADF;
    return inode->fops->write(desc, buffer, count);
}

int file_description_mmap(file_description* desc, uintptr_t addr, size_t length,
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

int file_description_truncate(file_description* desc, off_t length) {
    struct inode* inode = desc->inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;
    if (!inode->fops->truncate)
        return -EROFS;
    if (!(desc->flags & O_WRONLY))
        return -EBADF;
    return inode->fops->truncate(desc, length);
}

off_t file_description_seek(file_description* desc, off_t offset, int whence) {
    switch (whence) {
    case SEEK_SET:
        if (offset < 0)
            return -EINVAL;
        mutex_lock(&desc->offset_lock);
        desc->offset = offset;
        mutex_unlock(&desc->offset_lock);
        return offset;
    case SEEK_CUR:
        mutex_lock(&desc->offset_lock);
        off_t new_offset = desc->offset + offset;
        if (new_offset < 0) {
            mutex_unlock(&desc->offset_lock);
            return -EINVAL;
        }
        desc->offset = new_offset;
        mutex_unlock(&desc->offset_lock);
        return new_offset;
    case SEEK_END: {
        struct stat stat;
        inode_ref(desc->inode);
        int rc = inode_stat(desc->inode, &stat);
        if (IS_ERR(rc))
            return rc;
        off_t new_offset = stat.st_size + offset;
        if (new_offset < 0)
            return -EINVAL;
        mutex_lock(&desc->offset_lock);
        desc->offset = new_offset;
        mutex_unlock(&desc->offset_lock);
        return new_offset;
    }
    default:
        return -EINVAL;
    }
}

int file_description_ioctl(file_description* desc, int request,
                           void* user_argp) {
    struct inode* inode = desc->inode;
    if (!inode->fops->ioctl)
        return -ENOTTY;
    return inode->fops->ioctl(desc, request, user_argp);
}

int file_description_getdents(file_description* desc,
                              getdents_callback_fn callback, void* ctx) {
    struct inode* inode = desc->inode;
    if (!inode->fops->getdents || !S_ISDIR(inode->mode))
        return -ENOTDIR;

    return inode->fops->getdents(desc, callback, ctx);
}

int file_description_block(file_description* desc,
                           bool (*should_unblock)(file_description*)) {
    if ((desc->flags & O_NONBLOCK) && !should_unblock(desc))
        return -EAGAIN;
    return scheduler_block((should_unblock_fn)should_unblock, desc);
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
