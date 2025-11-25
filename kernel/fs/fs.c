#include "fs.h"
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stdio.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/poll.h>
#include <kernel/device/device.h>
#include <kernel/lock.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/sched.h>

static struct slab file_slab;
static struct slab filemap_slab;

void vfs_init(const multiboot_module_t* initrd_mod);
void pipe_init(void);

void fs_init(const multiboot_module_t* initrd_mod) {
    slab_init(&file_slab, sizeof(struct file));
    slab_init(&filemap_slab, sizeof(struct filemap));
    vfs_init(initrd_mod);
    pipe_init();
}

static void filemap_destroy(struct filemap* filemap) {
    if (!filemap)
        return;
    pages_clear(&filemap->pages);
    slab_free(&filemap_slab, filemap);
}

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

    ASSERT(inode->iops->destroy);
    filemap_destroy(inode->filemap);
    inode_unref(inode->pipe);
    inode_unref(inode->bound_socket);
    inode->iops->destroy(inode);
}

struct inode* inode_lookup(struct inode* parent, const char* name) {
    if (!parent->iops->lookup || !S_ISDIR(parent->mode)) {
        inode_unref(parent);
        return ERR_PTR(-ENOTDIR);
    }
    return parent->iops->lookup(parent, name);
}

int inode_link(struct inode* parent, const char* name, struct inode* child) {
    int rc = 0;
    if (!parent->iops->link || !S_ISDIR(parent->mode)) {
        rc = -ENOTDIR;
        goto fail;
    }
    if (parent->mount != child->mount) {
        rc = -EXDEV;
        goto fail;
    }
    return parent->iops->link(parent, name, child);

fail:
    inode_unref(parent);
    inode_unref(child);
    return rc;
}

int inode_unlink(struct inode* parent, const char* name) {
    if (!parent->iops->unlink || !S_ISDIR(parent->mode)) {
        inode_unref(parent);
        return -ENOTDIR;
    }
    return parent->iops->unlink(parent, name);
}

NODISCARD static int do_truncate(struct file* file, uint64_t length) {
    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;
    if (S_ISDIR(inode->mode))
        return -EISDIR;

    ASSERT(file->fops->truncate);

    int rc = 0;
    mutex_lock(&inode->lock);

    uint64_t old_size = inode->size;
    if (old_size == length)
        goto unlock_inode;

    file_lock(file);

    rc = file->fops->truncate(file, length);
    if (IS_ERR(rc))
        goto unlock_file;

    inode->size = length;

    if (length < old_size) {
        size_t end = DIV_CEIL(length, PAGE_SIZE);

        bool freed_pages = pages_truncate(&filemap->pages, end);
        size_t page_offset = length % PAGE_SIZE;
        if (page_offset > 0) {
            struct page* page = pages_get(filemap->pages, end - 1);
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

struct file* inode_open(struct inode* inode, int flags) {
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

    const struct file_ops* fops;
    switch (inode->mode & S_IFMT) {
    case S_IFCHR:
        fops = &char_dev_fops;
        break;
    case S_IFBLK:
        fops = &block_dev_fops;
        break;
    case S_IFIFO:
        fops = &pipe_fops;
        break;
    default:
        fops = inode->fops;
        break;
    }

    struct file* file = slab_alloc(&file_slab);
    if (IS_ERR(file)) {
        inode_unref(inode);
        return file;
    }
    *file = (struct file){
        .vm_obj = {.vm_ops = &file_vm_ops, .ref_count = 1},
        .inode = inode,
        .fops = fops,
        .filemap = inode->filemap,
        .flags = flags,
    };

    if (file->fops->open) {
        int rc = file->fops->open(file);
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
        if (file->fops->truncate) {
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
        .st_ino = inode->ino,
        .st_dev = inode->mount->dev,
        .st_mode = inode->mode,
        .st_rdev = inode->rdev,
        .st_size = inode->size,
        .st_blksize = 1 << inode->block_bits,
        .st_blocks = inode->blocks,
    };
    mutex_unlock(&inode->lock);
    inode_unref(inode);
    return 0;
}

int mount_commit_inode(struct mount* mount, struct inode* inode) {
    ASSERT(!(inode->flags & INODE_READY));
    ASSERT(inode->iops);
    ASSERT(inode->fops);
    ASSERT(inode->ino > 0);
    ASSERT(inode->mode & S_IFMT);
    ASSERT(inode->ref_count > 0);
    ASSERT(!inode->next);

    struct filemap* filemap = slab_alloc(&filemap_slab);
    if (IS_ERR(filemap)) {
        inode_unref(inode);
        return PTR_ERR(filemap);
    }
    *filemap = (struct filemap){
        .inode = inode,
    };
    inode->filemap = filemap;

    inode->mount = mount;
    inode->flags |= INODE_READY;

    mutex_lock(&mount->lock);
    for (struct inode* it = mount->inodes; it; it = it->next)
        ASSERT(it->ino != inode->ino);
    inode->next = mount->inodes;
    mount->inodes = inode;
    mutex_unlock(&mount->lock);

    return 0;
}

struct inode* mount_create_inode(struct mount* mount, mode_t mode) {
    ASSERT(mode & S_IFMT);

    const struct fs_ops* fs_ops = mount->fs->fs_ops;
    if (!fs_ops->create_inode)
        return ERR_PTR(-EROFS);

    struct inode* child = fs_ops->create_inode(mount, mode);
    if (IS_ERR(child))
        return child;

    inode_ref(child);
    int rc = mount_commit_inode(mount, child);
    if (IS_ERR(rc)) {
        inode_unref(child);
        return ERR_PTR(rc);
    }

    return child;
}

struct inode* mount_lookup_inode(struct mount* mount, ino_t ino) {
    ASSERT(ino > 0);
    mutex_lock(&mount->lock);
    struct inode* inode = mount->inodes;
    for (; inode; inode = inode->next) {
        if (inode->ino == ino)
            break;
    }
    if (inode)
        inode_ref(inode);
    mutex_unlock(&mount->lock);
    return inode;
}

void mount_set_root(struct mount* mount, struct inode* inode) {
    ASSERT(inode->flags & INODE_READY);
    ASSERT(inode->ref_count > 0);

    mutex_lock(&mount->lock);
    ASSERT(!mount->root);
    mount->root = inode;
    mutex_unlock(&mount->lock);
}

int mount_sync(struct mount* mount) {
    int rc = 0;
    mutex_lock(&mount->lock);
    for (struct inode* inode = mount->inodes; inode; inode = inode->next) {
        if (!(inode->flags & INODE_DIRTY))
            continue;

        inode_ref(inode);
        struct file* file = inode_open(inode, O_WRONLY);
        if (IS_ERR(file)) {
            rc = PTR_ERR(file);
            break;
        }

        rc = file_sync(file, 0, UINT64_MAX);
        file_unref(file);
        if (IS_ERR(rc))
            break;
    }
    mutex_unlock(&mount->lock);
    return rc;
}

NODISCARD static int populate_page(struct page* page, struct inode* inode) {
    ASSERT(mutex_is_locked_by_current(&inode->lock));
    ASSERT(inode->iops->pread);

    uint64_t byte_offset = (uint64_t)page->index << PAGE_SHIFT;

    unsigned char buf[PAGE_SIZE];
    unsigned char* dest = buf;
    size_t to_read = MIN(PAGE_SIZE, inode->size - byte_offset);
    while (to_read > 0) {
        ssize_t nread = inode->iops->pread(inode, dest, to_read, byte_offset);
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
    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;
    ASSERT(mutex_is_locked_by_current(&inode->lock));
    ASSERT(mutex_is_locked_by_current(&file->vm_obj.lock));
    if (!(page->flags & PAGE_DIRTY))
        return 0;

    ASSERT(inode->iops->pwrite);

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
                inode->iops->pwrite(inode, src, to_write, byte_offset);
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

static struct page* ensure_page(struct filemap* filemap, size_t index,
                                bool write) {
    struct inode* inode = filemap->inode;
    ASSERT(mutex_is_locked_by_current(&inode->lock));

    struct page* page = pages_get(filemap->pages, index);
    if (page)
        return page;

    uint64_t byte_offset = (uint64_t)index << PAGE_SHIFT;
    if (byte_offset >= inode->size) {
        if (write) {
            page = pages_alloc_at(&filemap->pages, index);
            if (IS_ERR(page))
                return page;
            page_fill(page, 0, 0, PAGE_SIZE);
            return page;
        }
        return NULL;
    }

    page = pages_alloc_at(&filemap->pages, index);
    if (IS_ERR(page))
        return page;

    int rc = populate_page(page, inode);
    if (IS_ERR(rc)) {
        pages_free(&filemap->pages, page);
        return ERR_PTR(rc);
    }

    return page;
}

static void file_destroy(struct vm_obj* obj) {
    struct file* file = CONTAINER_OF(obj, struct file, vm_obj);
    struct inode* inode = file->inode;
    if (file->fops->close)
        file->fops->close(file);
    slab_free(&file_slab, file);
    inode_unref(inode);
}

static struct page* file_get_page(struct vm_obj* obj, size_t index,
                                  uint32_t error_code) {
    ASSERT(mutex_is_locked_by_current(&obj->lock));
    struct file* file = CONTAINER_OF(obj, struct file, vm_obj);
    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;
    mutex_lock(&inode->lock);
    struct page* page = ensure_page(filemap, index, true);
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
    file_lock(file);
    ssize_t nread = file_pread(file, buffer, count, file->offset);
    if (IS_OK(nread))
        file->offset += nread;
    file_unlock(file);
    return nread;
}

static ssize_t default_file_pread(struct file* file, void* buffer, size_t count,
                                  uint64_t offset) {
    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;
    if (!inode->iops->pread)
        return -EINVAL;
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
        struct page* page = ensure_page(filemap, page_index, false);
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

ssize_t file_pread(struct file* file, void* buffer, size_t count,
                   uint64_t offset) {
    if (S_ISDIR(file->inode->mode))
        return -EISDIR;
    if ((file->flags & O_ACCMODE) == O_WRONLY)
        return -EBADF;
    if (offset + count < offset)
        return -EOVERFLOW;
    if (file->fops->pread)
        return file->fops->pread(file, buffer, count, offset);
    return default_file_pread(file, buffer, count, offset);
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
    file_lock(file);
    ssize_t nwritten = file_pwrite(file, buffer, count, file->offset);
    if (IS_OK(nwritten))
        file->offset += nwritten;
    file_unlock(file);
    return nwritten;
}

static ssize_t default_file_pwrite(struct file* file, const void* buffer,
                                   size_t count, uint64_t offset) {
    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;
    if (!inode->iops->pwrite)
        return -EINVAL;
    const unsigned char* src = buffer;
    size_t nwritten = 0;
    size_t page_index = offset >> PAGE_SHIFT;
    size_t page_offset = offset % PAGE_SIZE;
    mutex_lock(&inode->lock);
    while (nwritten < count) {
        struct page* page = ensure_page(filemap, page_index, true);
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

ssize_t file_pwrite(struct file* file, const void* buffer, size_t count,
                    uint64_t offset) {
    if (S_ISDIR(file->inode->mode))
        return -EISDIR;
    if ((file->flags & O_ACCMODE) == O_RDONLY)
        return -EBADF;
    if (offset + count < offset)
        return -EOVERFLOW;
    if (file->fops->pwrite)
        return file->fops->pwrite(file, buffer, count, offset);
    return default_file_pwrite(file, buffer, count, offset);
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
    if (!file->fops->truncate)
        return -EINVAL;
    if ((file->flags & O_ACCMODE) == O_RDONLY)
        return -EINVAL;
    return do_truncate(file, length);
}

loff_t file_seek(struct file* file, loff_t offset, int whence) {
    struct inode* inode = file->filemap->inode;
    switch (inode->mode & S_IFMT) {
    case S_IFREG:
    case S_IFBLK:
    case S_IFLNK:
        break;
    default:
        return -ESPIPE;
    }

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
    if (!file->fops->ioctl)
        return -ENOTTY;
    return file->fops->ioctl(file, request, user_argp);
}

int file_getdents(struct file* file, getdents_callback_fn callback, void* ctx) {
    if (!file->fops->getdents || !S_ISDIR(file->inode->mode))
        return -ENOTDIR;

    return file->fops->getdents(file, callback, ctx);
}

short file_poll(struct file* file, short events) {
    if (!file->fops->poll)
        return events & (POLLIN | POLLOUT);
    short revents = file->fops->poll(file, events);
    ASSERT(revents >= 0);
    if (!(events & POLLIN))
        ASSERT(!(revents & POLLIN));
    if (!(events & POLLOUT))
        ASSERT(!(revents & POLLOUT));
    return revents;
}

NODISCARD static int do_fsync(struct file* file) {
    if (file->fops->fsync)
        return file->fops->fsync(file);
    struct inode* inode = file->filemap->inode;
    if (inode->iops->fsync)
        return inode->iops->fsync(inode);
    return 0;
}

int file_sync(struct file* file, uint64_t offset, uint64_t nbytes) {
    if (nbytes == 0)
        return 0;

    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;
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

    size_t num_successful = 0;
    for (struct page* page = filemap->pages; page; page = page->next) {
        if (end <= page->index)
            break;
        if (page->index < start)
            continue;
        rc = writeback_page(page, file);
        if (IS_ERR(rc))
            break;
        ++num_successful;
    }

    if (num_successful > 0) {
        int fsync_rc = do_fsync(file);
        if (IS_OK(rc))
            rc = fsync_rc;
    }

    bool has_any_dirty_pages = false;
    for (const struct page* page = filemap->pages; page; page = page->next) {
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
    if (file->fops->mmap)
        return file->fops->mmap(file);
    struct vm_obj* obj = &file->vm_obj;
    vm_obj_ref(obj);
    return obj;
}

int file_block(struct file* file, bool (*unblock)(struct file*), int flags) {
    if ((file->flags & O_NONBLOCK) && !unblock(file))
        return -EAGAIN;
    return sched_block((unblock_fn)unblock, file, flags);
}
