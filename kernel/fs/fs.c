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
    ASSERT(inode->fops->destroy_inode);
    pages_clear(&inode->shared_pages);
    inode_unref(inode->fifo);
    if (inode->bound_socket)
        inode_unref(&inode->bound_socket->inode);
    inode->fops->destroy_inode(inode);
}

static struct page* do_get_page(struct inode* inode, size_t offset) {
    struct page* page = pages_get(inode->shared_pages, offset);
    if (page)
        return page;

    int ret = 0;
    struct file* file = NULL;

    page = pages_alloc_at(&inode->shared_pages, offset);
    if (IS_ERR(page)) {
        ret = PTR_ERR(page);
        page = NULL;
        goto fail;
    }

    inode_ref(inode);
    file = inode_open(inode, O_RDONLY, 0);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        file = NULL;
        goto fail;
    }

    ASSERT(inode->fops->pread);
    void* kaddr = kmap_page(page);
    unsigned char* dest = kaddr;
    size_t to_read = PAGE_SIZE;
    uint64_t file_offset = (uint64_t)offset * PAGE_SIZE;
    while (to_read > 0) {
        ssize_t nread = inode->fops->pread(file, dest, to_read, file_offset);
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
    pages_free(&inode->shared_pages, page);
    return ERR_PTR(ret);
}

static struct page* inode_get_page(struct vm_obj* obj, size_t offset,
                                   uint32_t error_code) {
    struct inode* inode = CONTAINER_OF(obj, struct inode, vm_obj);
    struct page* page = do_get_page(inode, offset);
    if (IS_ERR(page))
        return page;
    if (error_code & X86_PF_WRITE) {
        inode->flags |= INODE_DIRTY;
        page->flags |= PAGE_DIRTY;
    }
    return page;
}

const struct vm_ops inode_vm_ops = {
    .destroy_obj = inode_destroy,
    .get_page = inode_get_page,
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

void inode_lock(struct inode* inode) { mutex_lock(&inode->vm_obj.lock); }

void inode_unlock(struct inode* inode) { mutex_unlock(&inode->vm_obj.lock); }

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

void* inode_map(struct inode* inode, size_t length, unsigned vm_flags,
                size_t pgoff) {
    size_t npages = DIV_CEIL(length, PAGE_SIZE);
    mutex_lock(&kernel_vm->lock);

    struct vm_region* region = vm_alloc(kernel_vm, npages);
    if (IS_ERR(region)) {
        mutex_unlock(&kernel_vm->lock);
        inode_unref(inode);
        return region;
    }

    ASSERT_OK(vm_region_set_flags(region, 0, npages, vm_flags, ~0));
    vm_region_set_obj(region, &inode->vm_obj, pgoff);

    mutex_unlock(&kernel_vm->lock);
    return vm_region_to_virt(region);
}

void inode_unmap(void* virt_addr) {
    if (!virt_addr)
        return;

    mutex_lock(&kernel_vm->lock);
    struct vm_region* region = vm_find(kernel_vm, virt_addr);
    ASSERT(region);
    ASSERT(virt_addr == vm_region_to_virt(region));
    ASSERT_OK(vm_region_free(region, 0, region->end - region->start));
    mutex_unlock(&kernel_vm->lock);
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

static bool inode_is_cached(const struct inode* inode) {
    if (inode->flags & INODE_NO_PAGE_CACHE)
        return false;
    switch (inode->mode & S_IFMT) {
    case S_IFREG:
    case S_IFBLK:
    case S_IFLNK:
        return true;
    }
    return false;
}

void file_ref(struct file* file) {
    ASSERT(file);
    ASSERT(file->ref_count++ > 0);
}

void file_unref(struct file* file) {
    if (!file)
        return;
    ASSERT(file->ref_count > 0);
    if (--file->ref_count > 0)
        return;

    int rc = file_sync(file, 0, UINT64_MAX);
    (void)rc;
    struct inode* inode = file->inode;
    if (inode->fops->close)
        inode->fops->close(file);
    slab_cache_free(&file_cache, file);
    inode_unref(inode);
}

static struct page* get_cached_page(struct file* file, size_t offset,
                                    bool write) {
    struct inode* inode = file->inode;
    struct vm_obj* vm_obj = &inode->vm_obj;
    ASSERT(mutex_is_locked_by_current(&vm_obj->lock));

    struct page* page = pages_get(inode->shared_pages, offset);
    if (page)
        return page;

    page = pages_alloc_at(&inode->shared_pages, offset);
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
            pages_free(&inode->shared_pages, page);
            return ERR_PTR(nread);
        }
        if (nread == 0) {
            if (!write && page_offset == 0) {
                // Out of bounds
                kunmap(kaddr);
                pages_free(&inode->shared_pages, page);
                return NULL;
            }
            memset(kaddr + page_offset, 0, to_read);
            break;
        }
        page_offset += nread;
        file_offset += nread;
    }
    kunmap(kaddr);
    return page;
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
    if (!inode_is_cached(inode))
        return inode->fops->pread(file, buffer, count, offset);

    size_t page_index = offset / PAGE_SIZE;
    size_t page_offset = offset % PAGE_SIZE;
    unsigned char* dest = buffer;
    size_t nread = 0;
    inode_lock(inode);
    while (nread < count) {
        struct page* page = get_cached_page(file, page_index, false);
        if (IS_ERR(page)) {
            inode_unlock(inode);
            return PTR_ERR(page);
        }
        if (!page)
            break;
        unsigned char* kaddr = kmap_page(page);
        size_t to_read = MIN(count - nread, PAGE_SIZE - page_offset);
        memcpy(dest, kaddr + page_offset, to_read);
        kunmap(kaddr);
        dest += to_read;
        nread += to_read;
        ++page_index;
        page_offset = 0;
    }
    inode_unlock(inode);
    return nread;
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
    if (!inode_is_cached(inode))
        return inode->fops->pwrite(file, buffer, count, offset);

    inode_lock(inode);
    size_t page_index = offset / PAGE_SIZE;
    size_t page_offset = offset % PAGE_SIZE;
    const unsigned char* src = buffer;
    size_t nwritten = 0;
    while (nwritten < count) {
        struct page* page = get_cached_page(file, page_index, true);
        if (IS_ERR(page)) {
            inode_unlock(inode);
            return PTR_ERR(page);
        }
        ASSERT(page);

        unsigned char* kaddr = kmap_page(page);
        size_t to_write = MIN(count - nwritten, PAGE_SIZE - page_offset);
        memcpy(kaddr + page_offset, src, to_write);
        kunmap(kaddr);

        page->flags |= PAGE_DIRTY;
        inode->flags |= INODE_DIRTY;

        src += to_write;
        nwritten += to_write;
        ++page_index;
        page_offset = 0;
    }
    inode_unlock(inode);
    return nwritten;
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

static void do_truncate(struct page** pages, uint64_t length) {
    size_t end = length / PAGE_SIZE;
    pages_truncate(pages, end + 1);
    size_t page_offset = length % PAGE_SIZE;
    if (page_offset == 0)
        return;
    struct page* page = pages_get(*pages, end);
    if (!page)
        return;
    unsigned char* kaddr = kmap_page(page);
    memset(kaddr + page_offset, 0, PAGE_SIZE - page_offset);
    kunmap(kaddr);
}

int file_truncate(struct file* file, uint64_t length) {
    struct inode* inode = file->inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;
    if (!inode->fops->truncate)
        return -EINVAL;
    if ((file->flags & O_ACCMODE) == O_RDONLY)
        return -EINVAL;
    int rc = inode->fops->truncate(file, length);
    if (IS_ERR(rc))
        return rc;
    inode_lock(inode);
    do_truncate(&inode->shared_pages, length);
    /*for (struct vm_region* region = vm_obj->shared_regions; region;
         region = region->shared_next) {
        struct vm* vm = region->vm;
        mutex_lock(&vm->lock);
        // Unmap the pages
        mutex_unlock(&vm->lock);
    }*/
    inode_unlock(inode);
    return 0;
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

NODISCARD static int sync_page(struct file* file, struct page* page) {
    struct inode* inode = file->inode;
    ASSERT(mutex_is_locked_by_current(&inode->vm_obj.lock));
    if (!(page->flags & PAGE_DIRTY))
        return 0;

    ASSERT(inode->fops->pwrite);
    page->flags &= ~PAGE_DIRTY;

    void* kaddr = kmap_page(page);
    const unsigned char* src = kaddr;
    size_t to_write = PAGE_SIZE;
    uint64_t file_offset = (uint64_t)page->offset * PAGE_SIZE;
    while (to_write > 0) {
        ssize_t nwritten =
            inode->fops->pwrite(file, src, to_write, file_offset);
        if (IS_ERR(nwritten)) {
            kunmap(kaddr);
            page->flags |= PAGE_DIRTY;
            return nwritten;
        }
        if (nwritten == 0)
            break;
        src += nwritten;
        to_write -= nwritten;
        file_offset += nwritten;
    }
    kunmap(kaddr);
    return 0;
}

int file_sync(struct file* file, uint64_t offset, uint64_t nbytes) {
    if (nbytes == 0)
        return 0;
    struct inode* inode = file->inode;
    if (!(inode->flags & INODE_DIRTY))
        return 0;
    size_t start = offset / PAGE_SIZE;
    size_t end = DIV_CEIL(offset + nbytes, PAGE_SIZE);
    if (end <= start) {
        // Overflow
        end = SIZE_MAX;
    }
    int rc = 0;
    inode_lock(inode);
    struct page* page = inode->shared_pages;
    for (; page; page = page->next) {
        if (end <= page->offset)
            break;
        if (page->offset < start)
            continue;
        rc = sync_page(file, page);
        if (IS_ERR(rc))
            break;
    }
    inode_unlock(inode);
    return rc;
}

int file_block(struct file* file, bool (*unblock)(struct file*), int flags) {
    if ((file->flags & O_NONBLOCK) && !unblock(file))
        return -EAGAIN;
    return sched_block((unblock_fn)unblock, file, flags);
}
