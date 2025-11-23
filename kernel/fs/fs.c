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

void inode_ref(struct inode* inode) {
    ASSERT(inode);
    ASSERT(inode->ref_count++ > 0);
}

void inode_unref(struct inode* inode) {
    if (!inode)
        return;
    ASSERT(inode->ref_count > 0);
    if (--inode->ref_count > 0)
        return;

    ASSERT(inode->fops->destroy_inode);
    pages_clear(&inode->shared_pages);
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

static struct slab file_slab;

void file_init(void) { slab_init(&file_slab, sizeof(struct file)); }

NODISCARD static int do_truncate(struct file* file, uint64_t length) {
    struct inode* inode = file->inode;
    ASSERT(inode->fops->truncate);
    if (S_ISDIR(inode->mode))
        return -EISDIR;

    int rc = 0;
    mutex_lock(&inode->lock);

    uint64_t old_size = inode->size;
    if (old_size == length)
        goto unlock_inode;

    file_lock(file);

    rc = inode->fops->truncate(file, length);
    if (IS_ERR(rc))
        goto unlock_file;

    inode->size = length;

    if (length < old_size) {
        size_t end = DIV_CEIL(length, PAGE_SIZE);

        bool freed_pages = pages_truncate(&inode->shared_pages, end);
        size_t page_offset = length % PAGE_SIZE;
        if (page_offset > 0) {
            struct page* page = pages_get(inode->shared_pages, end - 1);
            if (page)
                page_fill(page, 0, page_offset, PAGE_SIZE - page_offset);
        }

        if (freed_pages)
            rc = vm_obj_invalidate_mappings(&file->vm_obj, end, SIZE_MAX);
    }

unlock_file:
    file_unlock(file);
unlock_inode:
    mutex_unlock(&inode->lock);
    return rc;
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

    struct file* file = slab_alloc(&file_slab);
    if (IS_ERR(file)) {
        inode_unref(inode);
        return file;
    }
    *file = (struct file){
        .vm_obj = {.vm_ops = &file_vm_ops, .ref_count = 1},
        .inode = inode,
        .flags = flags,
    };

    if (inode->fops->open) {
        int rc = inode->fops->open(file, mode);
        if (IS_ERR(rc)) {
            inode_unref(inode);
            slab_free(&file_slab, file);
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
            int rc = do_truncate(file, 0);
            if (IS_ERR(rc)) {
                file_unref(file);
                return ERR_PTR(rc);
            }
        }
    }

    return file;
}

int inode_stat(struct inode* inode, struct kstat* buf) {
    mutex_lock(&inode->lock);
    *buf = (struct kstat){
        .st_dev = inode->dev,
        .st_mode = inode->mode,
        .st_nlink = inode->num_links,
        .st_rdev = inode->rdev,
        .st_size = inode->size,
        .st_blksize = 1 << inode->block_bits,
        .st_blocks = inode->blocks,
    };
    mutex_unlock(&inode->lock);
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

static bool inode_is_cacheable(const struct inode* inode) {
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

NODISCARD static int populate_page(struct page* page, struct file* file) {
    struct inode* inode = file->inode;
    ASSERT(mutex_is_locked_by_current(&inode->lock));
    ASSERT(inode->fops->pread);

    uint64_t byte_offset = (uint64_t)page->index << PAGE_SHIFT;

    unsigned char buf[PAGE_SIZE];
    unsigned char* dest = buf;
    size_t to_read = MIN(PAGE_SIZE, inode->size - byte_offset);
    while (to_read > 0) {
        ssize_t nread = inode->fops->pread(file, dest, to_read, byte_offset);
        if (IS_ERR(nread))
            return nread;
        if (nread == 0) {
            memset(dest, 0, to_read);
            break;
        }
        dest += nread;
        to_read -= nread;
        byte_offset += nread;
    }
    page_copy_from_buffer(page, buf, 0, PAGE_SIZE);

    return 0;
}

NODISCARD static int writeback_page(struct page* page, struct file* file) {
    struct inode* inode = file->inode;
    ASSERT(mutex_is_locked_by_current(&inode->lock));
    ASSERT(mutex_is_locked_by_current(&file->vm_obj.lock));
    if (!(page->flags & PAGE_DIRTY))
        return 0;

    ASSERT(inode->fops->pwrite);

    // Invalidate the mappings to detect writes to the page again.
    // If another task attempts to write to this page during the writeback,
    // the page fault handling will be blocked until the writeback is done
    // because we hold the inode lock.
    int rc = vm_obj_invalidate_mappings(&file->vm_obj, page->index, 1);
    if (IS_ERR(rc))
        return rc;

    uint64_t byte_offset = (uint64_t)page->index << PAGE_SHIFT;
    if (inode->size > byte_offset) {
        size_t to_write = MIN(PAGE_SIZE, inode->size - byte_offset);

        unsigned char buf[PAGE_SIZE];
        page_copy_to_buffer(page, buf, 0, to_write);

        const unsigned char* src = buf;
        while (to_write > 0) {
            ssize_t nwritten =
                inode->fops->pwrite(file, src, to_write, byte_offset);
            if (IS_ERR(nwritten))
                return nwritten;
            if (nwritten == 0)
                break;
            src += nwritten;
            to_write -= nwritten;
            byte_offset += nwritten;
        }
    }

    page->flags &= ~PAGE_DIRTY;
    return 0;
}

static struct page* ensure_page(struct file* file, size_t index, bool write) {
    struct inode* inode = file->inode;
    ASSERT(mutex_is_locked_by_current(&inode->lock));

    struct page* page = pages_get(inode->shared_pages, index);
    if (page)
        return page;

    uint64_t byte_offset = (uint64_t)index << PAGE_SHIFT;
    if (byte_offset >= inode->size) {
        if (write) {
            page = pages_alloc_at(&inode->shared_pages, index);
            if (IS_ERR(page))
                return page;
            page_fill(page, 0, 0, PAGE_SIZE);
            return page;
        }
        return NULL;
    }

    page = pages_alloc_at(&inode->shared_pages, index);
    if (IS_ERR(page))
        return page;

    int rc = populate_page(page, file);
    if (IS_ERR(rc)) {
        pages_free(&inode->shared_pages, page);
        return ERR_PTR(rc);
    }

    return page;
}

static void file_destroy(struct vm_obj* obj) {
    struct file* file = CONTAINER_OF(obj, struct file, vm_obj);
    int rc = file_sync(file, 0, UINT64_MAX);
    (void)rc;
    struct inode* inode = file->inode;
    if (inode->fops->close)
        inode->fops->close(file);
    slab_free(&file_slab, file);
    inode_unref(inode);
}

static struct page* file_get_page(struct vm_obj* obj, size_t index,
                                  uint32_t error_code) {
    ASSERT(mutex_is_locked_by_current(&obj->lock));
    struct file* file = CONTAINER_OF(obj, struct file, vm_obj);
    struct inode* inode = file->inode;
    mutex_lock(&inode->lock);
    struct page* page = ensure_page(file, index, true);
    mutex_unlock(&inode->lock);
    if (IS_ERR(page))
        return page;
    ASSERT(page);
    if (error_code & X86_PF_WRITE) {
        page->flags |= PAGE_DIRTY;
        inode->flags |= INODE_DIRTY;
    }
    return page;
}

const struct vm_ops file_vm_ops = {
    .destroy_obj = file_destroy,
    .get_page = file_get_page,
};

void file_ref(struct file* file) {
    ASSERT(file);
    vm_obj_ref(&file->vm_obj);
}

void file_unref(struct file* file) {
    if (!file)
        return;
    vm_obj_unref(&file->vm_obj);
}

void file_lock(struct file* file) { mutex_lock(&file->vm_obj.lock); }

void file_unlock(struct file* file) { mutex_unlock(&file->vm_obj.lock); }

ssize_t file_read(struct file* file, void* buffer, size_t count) {
    struct inode* inode = file->inode;
    if (!inode_is_seekable(inode))
        return file_pread(file, buffer, count, 0);

    file_lock(file);
    ssize_t nread = file_pread(file, buffer, count, file->offset);
    if (IS_OK(nread))
        file->offset += nread;
    file_unlock(file);
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
    if (offset + count < offset)
        return -EOVERFLOW;
    if (!inode_is_cacheable(inode))
        return inode->fops->pread(file, buffer, count, offset);

    mutex_lock(&inode->lock);

    if (offset >= inode->size) {
        mutex_unlock(&inode->lock);
        return 0;
    }

    count = MIN(count, inode->size - offset);

    unsigned char* dest = buffer;
    size_t nread = 0;
    size_t page_index = offset >> PAGE_SHIFT;
    size_t page_offset = offset % PAGE_SIZE;
    while (nread < count) {
        struct page* page = ensure_page(file, page_index, false);
        if (IS_ERR(page)) {
            mutex_unlock(&inode->lock);
            return PTR_ERR(page);
        }
        if (!page)
            break;

        size_t to_read = MIN(count - nread, PAGE_SIZE - page_offset);
        page_copy_to_buffer(page, dest, page_offset, to_read);

        dest += to_read;
        nread += to_read;
        ++page_index;
        page_offset = 0;
    }

    mutex_unlock(&inode->lock);
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

    file_lock(file);
    ssize_t nwritten = file_pwrite(file, buffer, count, file->offset);
    if (IS_OK(nwritten))
        file->offset += nwritten;
    file_unlock(file);
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
    if (offset + count < offset)
        return -EOVERFLOW;
    if (!inode_is_cacheable(inode))
        return inode->fops->pwrite(file, buffer, count, offset);

    const unsigned char* src = buffer;
    size_t nwritten = 0;
    size_t page_index = offset >> PAGE_SHIFT;
    size_t page_offset = offset % PAGE_SIZE;
    mutex_lock(&inode->lock);
    while (nwritten < count) {
        struct page* page = ensure_page(file, page_index, true);
        if (IS_ERR(page)) {
            mutex_unlock(&inode->lock);
            return PTR_ERR(page);
        }
        ASSERT(page);

        size_t to_write = MIN(count - nwritten, PAGE_SIZE - page_offset);
        page_copy_from_buffer(page, src, page_offset, to_write);

        src += to_write;
        nwritten += to_write;
        ++page_index;
        page_offset = 0;

        page->flags |= PAGE_DIRTY;
        inode->flags |= INODE_DIRTY;
        inode->size = MAX(inode->size, offset + nwritten);
    }
    mutex_unlock(&inode->lock);
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

int file_truncate(struct file* file, uint64_t length) {
    struct inode* inode = file->inode;
    if (!inode->fops->truncate)
        return -EINVAL;
    if ((file->flags & O_ACCMODE) == O_RDONLY)
        return -EINVAL;
    return do_truncate(file, length);
}

loff_t file_seek(struct file* file, loff_t offset, int whence) {
    struct inode* inode = file->inode;
    if (!inode_is_seekable(inode))
        return -ESPIPE;
    switch (whence) {
    case SEEK_SET:
        if (offset < 0)
            return -EINVAL;
        file_lock(file);
        file->offset = offset;
        file_unlock(file);
        return offset;
    case SEEK_CUR:
        file_lock(file);
        loff_t new_offset = (loff_t)file->offset + offset;
        if (new_offset < 0) {
            file_unlock(file);
            return -EINVAL;
        }
        file->offset = new_offset;
        file_unlock(file);
        return new_offset;
    case SEEK_END: {
        mutex_lock(&inode->lock);
        loff_t size = (loff_t)inode->size;
        loff_t new_offset = size + offset;
        if (size < 0 || new_offset < 0) {
            mutex_unlock(&inode->lock);
            return -EINVAL;
        }
        file_lock(file);
        file->offset = new_offset;
        file_unlock(file);
        mutex_unlock(&inode->lock);
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

int file_sync(struct file* file, uint64_t offset, uint64_t nbytes) {
    if (nbytes == 0)
        return 0;

    struct inode* inode = file->inode;
    if (!(inode->flags & INODE_DIRTY))
        return 0;

    size_t start = offset >> PAGE_SHIFT;
    size_t end = DIV_CEIL(offset + nbytes, PAGE_SIZE);
    if (end <= start) {
        // Overflow
        end = SIZE_MAX;
    }

    int rc = 0;
    mutex_lock(&inode->lock);
    file_lock(file);

    for (struct page* page = inode->shared_pages; page; page = page->next) {
        if (end <= page->index)
            break;
        if (page->index < start)
            continue;
        rc = writeback_page(page, file);
        if (IS_ERR(rc))
            break;
    }

    bool has_any_dirty_pages = false;
    for (const struct page* page = inode->shared_pages; page;
         page = page->next) {
        if (page->flags & PAGE_DIRTY) {
            has_any_dirty_pages = true;
            break;
        }
    }
    if (!has_any_dirty_pages)
        inode->flags &= ~INODE_DIRTY;

    file_unlock(file);
    mutex_unlock(&inode->lock);
    return rc;
}

struct vm_obj* file_mmap(struct file* file) {
    if (file->inode->fops->mmap)
        return file->inode->fops->mmap(file);
    struct vm_obj* obj = &file->vm_obj;
    vm_obj_ref(obj);
    return obj;
}

int file_block(struct file* file, bool (*unblock)(struct file*), int flags) {
    if ((file->flags & O_NONBLOCK) && !unblock(file))
        return -EAGAIN;
    return sched_block((unblock_fn)unblock, file, flags);
}
