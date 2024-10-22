#include "fs.h"
#include <common/string.h>
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

static void inode_destroy(struct vm_obj* obj) {
    struct inode* inode = CONTAINER_OF(obj, struct inode, vm_obj);
    ASSERT(inode->num_links == 0);
    ASSERT(inode->fops->destroy_inode);
    inode_unref(inode->fifo);
    inode_unref(&inode->bound_socket->inode);
    inode->fops->destroy_inode(inode);
}

static struct page* inode_populate(struct vm_obj* obj, size_t offset,
                                   uint32_t error_code) {
    (void)error_code;

    int ret = 0;
    struct page* page = NULL;
    struct file* file = NULL;

    page = page_set_alloc_at(&obj->shared_pages, offset);
    if (IS_ERR(page)) {
        ret = PTR_ERR(page);
        page = NULL;
        goto fail;
    }

    struct inode* inode = CONTAINER_OF(obj, struct inode, vm_obj);
    const struct file_ops* fops = inode->fops;
    ASSERT(fops);
    ASSERT(fops->pread);

    inode_ref(inode);
    file = inode_open(inode, O_RDONLY, 0);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        file = NULL;
        goto fail;
    }

    void* kaddr = kmap_page(page);
    unsigned char* dest = kaddr;
    size_t to_read = PAGE_SIZE;
    uint64_t file_offset = (uint64_t)offset * PAGE_SIZE;
    while (to_read > 0) {
        ssize_t nread = fops->pread(file, dest, to_read, file_offset);
        if (IS_ERR(nread)) {
            kunmap(kaddr);
            ret = nread;
            goto fail;
        }
        if (nread == 0) {
            memset(dest, 0, to_read);
            break;
        }
        dest += nread;
        to_read -= nread;
        file_offset += nread;
    }
    kunmap(kaddr);

    file_unref(file);
    return page;

fail:
    file_unref(file);
    page_set_free(&obj->shared_pages, page);
    return ERR_PTR(ret);
}

static void inode_on_write(struct vm_obj* obj, struct page* page) {
    (void)obj;
    page->flags |= PAGE_DIRTY;
}

const struct vm_ops inode_vm_ops = {
    .destroy_obj = inode_destroy,
    .populate = inode_populate,
    .on_write = inode_on_write,
};

void inode_ref(struct inode* inode) {
    ASSERT(inode);
    vm_obj_ref(&inode->vm_obj);
}

void inode_unref(struct inode* inode) {
    if (!inode)
        return;
    vm_obj_unref(&inode->vm_obj);
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
        .inode = inode,
        .flags = flags,
        .ref_count = 1,
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
    ++file->ref_count;
}

void file_unref(struct file* file) {
    if (!file)
        return;
    ASSERT(file->ref_count > 0);
    if (--file->ref_count > 0)
        return;

    int rc = file_sync(file);
    (void)rc;
    struct inode* inode = file->inode;
    if (inode->fops->close)
        inode->fops->close(file);
    slab_cache_free(&file_cache, file);
    inode_unref(inode);
}

static void* map_cached_page(struct file* file, size_t offset, bool write) {
    struct inode* inode = file->inode;
    struct vm_obj* vm_obj = &inode->vm_obj;
    ASSERT(spinlock_is_locked_by_current(&vm_obj->lock));

    struct page* page = page_set_get(&vm_obj->shared_pages, offset);
    if (page)
        return kmap_page(page);

    page = page_set_alloc_at(&vm_obj->shared_pages, offset);
    if (IS_ERR(page))
        return page;

    ASSERT(inode->fops->pread);
    unsigned char* kaddr = kmap_page(page);
    size_t page_offset = 0;
    uint64_t file_offset = (uint64_t)offset * PAGE_SIZE;
    while (page_offset < PAGE_SIZE) {
        size_t to_read = PAGE_SIZE - page_offset;
        ssize_t nread =
            inode->fops->pread(file, kaddr + page_offset, to_read, file_offset);
        if (IS_ERR(nread)) {
            kunmap(kaddr);
            page_set_free(&vm_obj->shared_pages, page);
            return ERR_PTR(nread);
        }
        if (nread == 0) {
            if (!write && page_offset == 0) {
                // Out of bounds
                kunmap(kaddr);
                page_set_free(&vm_obj->shared_pages, page);
                return NULL;
            }
            memset(kaddr + page_offset, 0, to_read);
            break;
        }
        to_read -= nread;
        page_offset += nread;
        file_offset += nread;
    }

    if (write)
        page->flags |= PAGE_DIRTY;
    return kaddr;
}

ssize_t file_read(struct file* file, void* buffer, size_t count) {
    struct inode* inode = file->inode;
    if (!S_ISREG(inode->mode) && !S_ISBLK(inode->mode))
        return file_pread(file, buffer, count, 0);

    spinlock_lock(&file->offset_lock);
    ssize_t nread = file_pread(file, buffer, count, file->offset);
    if (IS_OK(nread))
        file->offset += nread;
    spinlock_unlock(&file->offset_lock);
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
    if (!S_ISREG(inode->mode) && !S_ISBLK(inode->mode))
        return inode->fops->pread(file, buffer, count, offset);

    struct vm_obj* vm_obj = &inode->vm_obj;
    size_t page_index = offset / PAGE_SIZE;
    size_t page_offset = offset % PAGE_SIZE;
    unsigned char* dest = buffer;
    size_t nread = 0;
    spinlock_lock(&vm_obj->lock);
    while (nread < count) {
        unsigned char* kaddr = map_cached_page(file, page_index, false);
        if (IS_ERR(kaddr)) {
            spinlock_unlock(&vm_obj->lock);
            return PTR_ERR(kaddr);
        }
        if (!kaddr)
            break;
        size_t to_read = MIN(count - nread, PAGE_SIZE - page_offset);
        memcpy(dest, kaddr + page_offset, to_read);
        kunmap(kaddr);
        dest += to_read;
        nread += to_read;
        ++page_index;
        page_offset = 0;
    }
    spinlock_unlock(&vm_obj->lock);
    return nread;
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
    struct inode* inode = file->inode;
    if (!S_ISREG(inode->mode) && !S_ISBLK(inode->mode))
        return file_pwrite(file, buffer, count, 0);

    spinlock_lock(&file->offset_lock);
    ssize_t nwritten = file_pwrite(file, buffer, count, file->offset);
    if (IS_OK(nwritten))
        file->offset += nwritten;
    spinlock_unlock(&file->offset_lock);
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
    if (!S_ISREG(inode->mode) && !S_ISBLK(inode->mode))
        return inode->fops->pwrite(file, buffer, count, offset);

    struct vm_obj* vm_obj = &inode->vm_obj;
    spinlock_lock(&vm_obj->lock);
    size_t page_index = offset / PAGE_SIZE;
    size_t page_offset = offset % PAGE_SIZE;
    const unsigned char* src = buffer;
    size_t nwritten = 0;
    while (nwritten < count) {
        unsigned char* kaddr = map_cached_page(file, page_index, true);
        if (IS_ERR(kaddr)) {
            spinlock_unlock(&vm_obj->lock);
            return PTR_ERR(kaddr);
        }
        ASSERT(kaddr);
        size_t to_write = MIN(count - nwritten, PAGE_SIZE - page_offset);
        memcpy(kaddr + page_offset, src, to_write);
        kunmap(kaddr);
        src += to_write;
        nwritten += to_write;
        ++page_index;
        page_offset = 0;
    }
    spinlock_unlock(&vm_obj->lock);
    return nwritten;
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
    struct inode* inode = file->inode;
    if (!S_ISREG(inode->mode) && !S_ISBLK(inode->mode))
        return -ESPIPE;
    switch (whence) {
    case SEEK_SET:
        if (offset < 0)
            return -EINVAL;
        spinlock_lock(&file->offset_lock);
        file->offset = offset;
        spinlock_unlock(&file->offset_lock);
        return offset;
    case SEEK_CUR:
        spinlock_lock(&file->offset_lock);
        loff_t new_offset = (loff_t)file->offset + offset;
        if (new_offset < 0) {
            spinlock_unlock(&file->offset_lock);
            return -EINVAL;
        }
        file->offset = new_offset;
        spinlock_unlock(&file->offset_lock);
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
        spinlock_lock(&file->offset_lock);
        file->offset = new_offset;
        spinlock_unlock(&file->offset_lock);
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

int file_sync(struct file* file) {
    struct inode* inode = file->inode;
    struct vm_obj* vm_obj = &inode->vm_obj;
    spinlock_lock(&vm_obj->lock);
    struct page* page = page_set_first(&vm_obj->shared_pages);
    for (; page; page = page->next) {
        if (!(page->flags & PAGE_DIRTY))
            continue;
        ASSERT(inode->fops->pwrite);
        page->flags &= ~PAGE_DIRTY;
        void* kaddr = kmap_page(page);
        unsigned char* src = kaddr;
        size_t to_write = PAGE_SIZE;
        uint64_t file_offset = (uint64_t)page->offset * PAGE_SIZE;
        while (to_write > 0) {
            ssize_t nwritten =
                inode->fops->pwrite(file, src, to_write, file_offset);
            if (IS_ERR(nwritten)) {
                kunmap(kaddr);
                spinlock_unlock(&vm_obj->lock);
                return nwritten;
            }
            if (nwritten == 0)
                break;
            src += nwritten;
            to_write -= nwritten;
            file_offset += nwritten;
        }
        kunmap(kaddr);
    }
    spinlock_unlock(&vm_obj->lock);
    return 0;
}

int file_block(struct file* file, bool (*unblock)(struct file*), int flags) {
    if ((file->flags & O_NONBLOCK) && !unblock(file))
        return -EAGAIN;
    return sched_block((unblock_fn)unblock, file, flags);
}
