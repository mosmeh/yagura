#include "fs.h"
#include <kernel/api/dirent.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stdio.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/poll.h>
#include <kernel/lock.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/sched.h>
#include <kernel/socket.h>

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
    inode_unref(inode->fifo);
    if (inode->bound_socket)
        inode_unref(&inode->bound_socket->inode);
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
    if (inode->dev != child->dev) {
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

struct file* inode_open(struct inode* inode, int flags, mode_t mode) {
    switch (flags & O_ACCMODE) {
    case O_RDONLY:
        break;
    case O_WRONLY:
    case O_RDWR:
        if (S_ISDIR(inode->mode)) {
            inode_unref(inode);
            return ERR_PTR(-EISDIR);
        }
        break;
    default:
        inode_unref(inode);
        return ERR_PTR(-EINVAL);
    }

    struct file* file = kmalloc(sizeof(struct file));
    if (!file) {
        inode_unref(inode);
        return ERR_PTR(-ENOMEM);
    }
    *file = (struct file){0};
    file->inode = inode;
    file->flags = flags;
    file->ref_count = 1;

    if (inode->fops->open) {
        int rc = inode->fops->open(file, mode);
        if (IS_ERR(rc)) {
            inode_unref(inode);
            kfree(file);
            return ERR_PTR(rc);
        }
    }

    if (flags & O_TRUNC) {
        if (S_ISDIR(inode->mode))
            return ERR_PTR(-EISDIR);
        // Truncation is performed even with O_RDONLY.
        if (inode->fops->truncate) {
            int rc = inode->fops->truncate(file, 0);
            if (IS_ERR(rc)) {
                file_close(file);
                return ERR_PTR(rc);
            }
        }
    }

    return file;
}

int inode_stat(struct inode* inode, struct kstat* buf) {
    *buf = (struct kstat){
        .st_dev = inode->dev,
        .st_mode = inode->mode,
        .st_nlink = inode->num_links,
        .st_rdev = inode->rdev,
    };
    if (inode->fops->stat)
        return inode->fops->stat(inode, buf);
    inode_unref(inode);
    return 0;
}

static bool inode_is_seekable(const struct inode* inode) {
    switch (inode->mode & S_IFMT) {
    case S_IFREG:
    case S_IFBLK:
    case S_IFLNK:
        return true;
    }
    return false;
}

int file_close(struct file* file) {
    ASSERT(file);
    ASSERT(file->ref_count > 0);
    if (--file->ref_count > 0)
        return 0;
    struct inode* inode = file->inode;
    int rc = 0;
    if (inode->fops->close)
        rc = inode->fops->close(file);
    kfree(file);
    inode_unref(inode);
    return rc;
}

ssize_t file_read(struct file* file, void* buffer, size_t count) {
    struct inode* inode = file->inode;
    if (!inode_is_seekable(inode))
        return file_pread(file, buffer, count, 0);

    mutex_lock(&file->offset_lock);
    ssize_t nread = file_pread(file, buffer, count, file->offset);
    if (IS_OK(nread))
        file->offset += nread;
    mutex_unlock(&file->offset_lock);
    return nread;
}

ssize_t file_pread(struct file* file, void* buffer, size_t count,
                   uint64_t offset) {
    struct inode* inode = file->inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;
    if (!inode->fops->pread)
        return -EINVAL;
    if ((file->flags & O_ACCMODE) == O_WRONLY)
        return -EBADF;
    return inode->fops->pread(file, buffer, count, offset);
}

ssize_t file_read_to_end(struct file* file, void* buffer, size_t count) {
    size_t cursor = 0;
    while (cursor < count) {
        ssize_t nread =
            file_read(file, (unsigned char*)buffer + cursor, count - cursor);
        if (IS_ERR(nread))
            return nread;
        if (nread == 0)
            break;
        cursor += nread;
    }
    return cursor;
}

ssize_t file_write(struct file* file, const void* buffer, size_t count) {
    struct inode* inode = file->inode;
    if (!inode_is_seekable(inode))
        return file_pwrite(file, buffer, count, 0);

    mutex_lock(&file->offset_lock);
    ssize_t nwritten = file_pwrite(file, buffer, count, file->offset);
    if (IS_OK(nwritten))
        file->offset += nwritten;
    mutex_unlock(&file->offset_lock);
    return nwritten;
}

ssize_t file_pwrite(struct file* file, const void* buffer, size_t count,
                    uint64_t offset) {
    struct inode* inode = file->inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;
    if (!inode->fops->pwrite)
        return -EINVAL;
    if ((file->flags & O_ACCMODE) == O_RDONLY)
        return -EBADF;
    return inode->fops->pwrite(file, buffer, count, offset);
}

ssize_t file_write_all(struct file* file, const void* buffer, size_t count) {
    size_t cursor = 0;
    while (cursor < count) {
        ssize_t nwritten = file_write(
            file, (const unsigned char*)buffer + cursor, count - cursor);
        if (IS_ERR(nwritten))
            return nwritten;
        if (nwritten == 0)
            break;
        cursor += nwritten;
    }
    return cursor;
}

void* file_mmap(struct file* file, size_t length, uint64_t offset, int flags) {
    struct inode* inode = file->inode;
    if (!inode->fops->mmap)
        return ERR_PTR(-ENODEV);
    if ((file->flags & O_ACCMODE) == O_WRONLY)
        return ERR_PTR(-EACCES);
    if ((flags & VM_SHARED) && (flags & VM_WRITE) &&
        ((file->flags & O_ACCMODE) != O_RDWR))
        return ERR_PTR(-EACCES);
    return inode->fops->mmap(file, length, offset, flags);
}

int file_truncate(struct file* file, uint64_t length) {
    struct inode* inode = file->inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;
    if (!inode->fops->truncate)
        return -EINVAL;
    if ((file->flags & O_ACCMODE) == O_RDONLY)
        return -EINVAL;
    return inode->fops->truncate(file, length);
}

loff_t file_seek(struct file* file, loff_t offset, int whence) {
    struct inode* inode = file->inode;
    if (!inode_is_seekable(inode))
        return -ESPIPE;
    switch (whence) {
    case SEEK_SET:
        if (offset < 0)
            return -EINVAL;
        mutex_lock(&file->offset_lock);
        file->offset = offset;
        mutex_unlock(&file->offset_lock);
        return offset;
    case SEEK_CUR:
        mutex_lock(&file->offset_lock);
        loff_t new_offset = (loff_t)file->offset + offset;
        if (new_offset < 0) {
            mutex_unlock(&file->offset_lock);
            return -EINVAL;
        }
        file->offset = new_offset;
        mutex_unlock(&file->offset_lock);
        return new_offset;
    case SEEK_END: {
        struct kstat stat;
        inode_ref(inode);
        int rc = inode_stat(inode, &stat);
        if (IS_ERR(rc))
            return rc;
        loff_t new_offset = (loff_t)stat.st_size + offset;
        if (new_offset < 0)
            return -EINVAL;
        mutex_lock(&file->offset_lock);
        file->offset = new_offset;
        mutex_unlock(&file->offset_lock);
        return new_offset;
    }
    default:
        return -EINVAL;
    }
}

int file_ioctl(struct file* file, int request, void* user_argp) {
    struct inode* inode = file->inode;
    if (!inode->fops->ioctl)
        return -ENOTTY;
    return inode->fops->ioctl(file, request, user_argp);
}

int file_getdents(struct file* file, getdents_callback_fn callback, void* ctx) {
    struct inode* inode = file->inode;
    if (!inode->fops->getdents || !S_ISDIR(inode->mode))
        return -ENOTDIR;

    return inode->fops->getdents(file, callback, ctx);
}

short file_poll(struct file* file, short events) {
    struct inode* inode = file->inode;
    if (!inode->fops->poll)
        return events & (POLLIN | POLLOUT);
    short revents = inode->fops->poll(file, events);
    ASSERT(revents >= 0);
    if (!(events & POLLIN))
        ASSERT(!(revents & POLLIN));
    if (!(events & POLLOUT))
        ASSERT(!(revents & POLLOUT));
    return revents;
}

int file_block(struct file* file, bool (*unblock)(struct file*), int flags) {
    if ((file->flags & O_NONBLOCK) && !unblock(file))
        return -EAGAIN;
    return sched_block((unblock_fn)unblock, file, flags);
}
