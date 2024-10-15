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

static struct slab_cache file_cache;

void file_init(void) { slab_cache_init(&file_cache, sizeof(struct file)); }

static void file_destroy(struct vobj* vobj) {
    struct file* file = CONTAINER_OF(vobj, struct file, vobj);
    struct inode* inode = file->inode;
    if (inode->fops->close)
        inode->fops->close(file);
    slab_cache_free(&file_cache, file);
    inode_unref(inode);
}

static struct vobj* file_clone(struct vobj* vobj) {
    struct file* file = CONTAINER_OF(vobj, struct file, vobj);
    file_ref(file);
    return vobj;
}

static bool file_handle_fault(struct vm_region* region, size_t offset,
                              uint32_t error_code) {
    (void)region;
    (void)offset;
    (void)error_code;
    UNIMPLEMENTED();
}

static const struct vm_ops file_vm_ops = {
    .destroy_vobj = file_destroy,
    .clone_vobj = file_clone,
    .handle_fault = file_handle_fault,
};

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

    struct file* file = slab_cache_alloc(&file_cache);
    if (IS_ERR(file)) {
        inode_unref(inode);
        return file;
    }
    *file = (struct file){
        .vobj =
            {
                .vm_ops = &file_vm_ops,
                .ref_count = 1,
            },
        .inode = inode,
        .flags = flags,
    };

    if (inode->fops->open) {
        int rc = inode->fops->open(file, mode);
        if (IS_ERR(rc)) {
            inode_unref(inode);
            slab_cache_free(&file_cache, file);
            return ERR_PTR(rc);
        }
    }

    if (flags & O_TRUNC) {
        if (S_ISDIR(inode->mode)) {
            file_unref(file);
            return ERR_PTR(-EISDIR);
        }
        // Truncation is performed even with O_RDONLY.
        if (inode->fops->truncate) {
            int rc = inode->fops->truncate(file, 0);
            if (IS_ERR(rc)) {
                file_unref(file);
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

void file_ref(struct file* file) {
    ASSERT(file);
    vobj_ref(&file->vobj);
}

void file_unref(struct file* file) {
    if (!file)
        return;
    vobj_unref(&file->vobj);
}

ssize_t file_read(struct file* file, void* buffer, size_t count) {
    if (!(file->inode->mode & (S_IFREG | S_IFBLK)))
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
        if (nread == -EINTR)
            continue;
        if (IS_ERR(nread))
            return nread;
        if (nread == 0)
            break;
        cursor += nread;
    }
    return cursor;
}

ssize_t file_write(struct file* file, const void* buffer, size_t count) {
    if (!(file->inode->mode & (S_IFREG | S_IFBLK)))
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
        ssize_t nwritten =
            file_write(file, (unsigned char*)buffer + cursor, count - cursor);
        if (nwritten == -EINTR)
            continue;
        if (IS_ERR(nwritten))
            return nwritten;
        if (nwritten == 0)
            break;
        cursor += nwritten;
    }
    return cursor;
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
    if (!(file->inode->mode & (S_IFREG | S_IFBLK)))
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
        inode_ref(file->inode);
        int rc = inode_stat(file->inode, &stat);
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
