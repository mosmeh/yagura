#include "fs.h"
#include "private.h"
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stdio.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/poll.h>
#include <kernel/device/device.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/lock.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/sched.h>

static struct slab file_slab;

void fs_init(const multiboot_module_t* initrd_mod) {
    slab_init(&file_slab, sizeof(struct file));
    path_init();
    filemap_init();
    vfs_init(initrd_mod);
    pipe_init();
}

struct inode* inode_ref(struct inode* inode) {
    ASSERT(inode);
    vm_obj_ref(&inode->vm_obj);
    return inode;
}

void inode_unref(struct inode* inode) {
    if (!inode)
        return;
    vm_obj_unref(&inode->vm_obj);
}

void inode_lock(struct inode* inode) { mutex_lock(&inode->vm_obj.lock); }

void inode_unlock(struct inode* inode) { mutex_unlock(&inode->vm_obj.lock); }

static void inode_destroy(struct vm_obj* obj) {
    struct inode* inode = CONTAINER_OF(obj, struct inode, vm_obj);
    ASSERT(inode->iops->destroy);
    filemap_destroy(inode->filemap);
    inode_unref(inode->pipe);
    inode_unref(inode->bound_socket);
    inode->iops->destroy(inode);
}

static struct page* inode_get_page(struct vm_obj* obj, size_t index,
                                   bool write) {
    ASSERT(mutex_is_locked_by_current(&obj->lock));
    struct inode* inode = CONTAINER_OF(obj, struct inode, vm_obj);
    struct page* page = filemap_ensure_page(inode->filemap, index, true);
    if (IS_ERR(ASSERT(page)))
        return page;
    if (write) {
        page->flags |= PAGE_DIRTY;
        inode->flags |= INODE_DIRTY;
    }
    return page;
}

const struct vm_ops inode_vm_ops = {
    .destroy_obj = inode_destroy,
    .get_page = inode_get_page,
};

struct inode* inode_lookup(struct inode* parent, const char* name) {
    if (!parent->iops->lookup || !S_ISDIR(parent->mode))
        return ERR_PTR(-ENOTDIR);
    return parent->iops->lookup(parent, name);
}

int inode_link(struct inode* parent, const char* name, struct inode* child) {
    if (!parent->iops->link || !S_ISDIR(parent->mode))
        return -ENOTDIR;
    if (parent->mount != child->mount)
        return -EXDEV;
    return parent->iops->link(parent, name, child);
}

int inode_unlink(struct inode* parent, const char* name) {
    if (!parent->iops->unlink || !S_ISDIR(parent->mode))
        return -ENOTDIR;
    return parent->iops->unlink(parent, name);
}

int inode_sync(struct inode* inode, uint64_t offset, uint64_t nbytes) {
    if (nbytes == 0)
        return 0;
    if (!(inode->flags & INODE_DIRTY))
        return 0;

    size_t start = offset >> PAGE_SHIFT;
    size_t end = DIV_CEIL(offset + nbytes, PAGE_SIZE);
    if (end <= start) {
        // Overflow
        end = SIZE_MAX;
    }

    inode_lock(inode);
    int rc = filemap_sync(inode->filemap, start, end);
    inode_unlock(inode);
    return rc;
}

int inode_truncate(struct inode* inode, uint64_t length) {
    if (!inode->iops->truncate)
        return -EINVAL;
    if (S_ISDIR(inode->mode))
        return -EISDIR;

    int rc = 0;
    inode_lock(inode);

    uint64_t old_size = inode->size;
    if (old_size == length)
        goto exit;

    rc = inode->iops->truncate(inode, length);
    if (IS_ERR(rc))
        goto exit;

    inode->size = length;

    if (length < old_size)
        rc = filemap_truncate(inode->filemap, length);

exit:
    inode_unlock(inode);
    return rc;
}

struct file* inode_open(struct inode* inode, int flags) {
    switch (flags & O_ACCMODE) {
    case O_RDONLY:
        break;
    case O_WRONLY:
    case O_RDWR:
        if (S_ISDIR(inode->mode))
            return ERR_PTR(-EISDIR);
        break;
    default:
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
    if (IS_ERR(ASSERT(file)))
        return file;
    *file = (struct file){
        .inode = inode,
        .fops = fops,
        .filemap = inode->filemap,
        .flags = flags,
        .refcount = REFCOUNT_INIT_ONE,
    };

    if (file->fops->open) {
        int rc = file->fops->open(file);
        if (IS_ERR(rc)) {
            slab_free(&file_slab, file);
            return ERR_PTR(rc);
        }
    }

    // Now the file struct is fully initialized.
    inode_ref(inode);

    if (flags & O_TRUNC) {
        if (S_ISDIR(inode->mode)) {
            file_unref(file);
            return ERR_PTR(-EISDIR);
        }
        // Truncation is performed even with O_RDONLY.
        if (inode->iops->truncate) {
            int rc = inode_truncate(inode, 0);
            if (IS_ERR(rc)) {
                file_unref(file);
                return ERR_PTR(rc);
            }
        }
    }

    return file;
}

int inode_stat(struct inode* inode, struct kstat* buf) {
    inode_lock(inode);
    *buf = (struct kstat){
        .st_ino = inode->ino,
        .st_dev = inode->mount->dev,
        .st_mode = inode->mode,
        .st_rdev = inode->rdev,
        .st_size = inode->size,
        .st_blksize = 1 << inode->block_bits,
        .st_blocks = inode->blocks,
    };
    inode_unlock(inode);
    return 0;
}

int mount_commit_inode(struct mount* mount, struct inode* inode) {
    ASSERT(!(inode->flags & INODE_READY));
    ASSERT(inode->iops);
    ASSERT(inode->fops);
    ASSERT(inode->ino > 0);
    ASSERT(inode->mode & S_IFMT);
    ASSERT(refcount_get(&inode->vm_obj.refcount) > 0);
    ASSERT(!inode->next);

    struct filemap* filemap = filemap_create(inode);
    if (IS_ERR(ASSERT(filemap)))
        return PTR_ERR(filemap);
    inode->filemap = filemap;

    inode->mount = mount;

    mutex_lock(&mount->lock);
    inode->flags |= INODE_READY;
    for (struct inode* it = mount->inodes; it; it = it->next)
        ASSERT(it->ino != inode->ino);
    inode->next = mount->inodes;
    mount->inodes = inode_ref(inode);
    mutex_unlock(&mount->lock);

    return 0;
}

struct inode* mount_create_inode(struct mount* mount, mode_t mode) {
    ASSERT(mode & S_IFMT);

    const struct fs_ops* fs_ops = mount->fs->fs_ops;
    if (!fs_ops->create_inode)
        return ERR_PTR(-EROFS);

    struct inode* child FREE(inode) = fs_ops->create_inode(mount, mode);
    if (IS_ERR(ASSERT(child)))
        return child;

    int rc = mount_commit_inode(mount, child);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    return TAKE_PTR(child);
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
    ASSERT(refcount_get(&inode->vm_obj.refcount) > 0);

    mutex_lock(&mount->lock);
    ASSERT(!mount->root);
    mount->root = inode_ref(inode);
    mutex_unlock(&mount->lock);
}

int mount_sync(struct mount* mount) {
    int rc = 0;
    mutex_lock(&mount->lock);
    for (struct inode* inode = mount->inodes; inode; inode = inode->next) {
        if (!(inode->flags & INODE_DIRTY))
            continue;
        rc = inode_sync(inode, 0, UINT64_MAX);
        if (IS_ERR(rc))
            break;
    }
    mutex_unlock(&mount->lock);
    return rc;
}

struct file* file_ref(struct file* file) {
    ASSERT(file);
    refcount_inc(&file->refcount);
    return file;
}

void file_unref(struct file* file) {
    if (!file)
        return;
    if (refcount_dec(&file->refcount))
        return;

    struct inode* inode = file->inode;
    if (file->fops->close)
        file->fops->close(file);
    slab_free(&file_slab, file);
    inode_unref(inode);
}

ssize_t file_read(struct file* file, void* buffer, size_t count) {
    mutex_lock(&file->lock);
    ssize_t nread = file_pread(file, buffer, count, file->offset);
    if (IS_OK(nread))
        file->offset += nread;
    mutex_unlock(&file->lock);
    return nread;
}

static ssize_t default_file_pread(struct file* file, void* buffer, size_t count,
                                  uint64_t offset) {
    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;
    if (!inode->iops->pread)
        return -EINVAL;
    inode_lock(inode);

    if (offset >= inode->size) {
        inode_unlock(inode);
        return 0;
    }

    count = MIN(count, inode->size - offset);

    unsigned char* dest = buffer;
    size_t nread = 0;
    size_t page_index = offset >> PAGE_SHIFT;
    size_t page_offset = offset % PAGE_SIZE;
    while (nread < count) {
        struct page* page = filemap_ensure_page(filemap, page_index, false);
        if (IS_ERR(page)) {
            inode_unlock(inode);
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

    inode_unlock(inode);
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

ssize_t file_write(struct file* file, const void* buffer, size_t count) {
    mutex_lock(&file->lock);
    ssize_t nwritten = file_pwrite(file, buffer, count, file->offset);
    if (IS_OK(nwritten))
        file->offset += nwritten;
    mutex_unlock(&file->lock);
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
    inode_lock(inode);
    while (nwritten < count) {
        struct page* page = filemap_ensure_page(filemap, page_index, true);
        if (IS_ERR(ASSERT(page))) {
            inode_unlock(inode);
            return PTR_ERR(page);
        }

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
    inode_unlock(inode);
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

int file_truncate(struct file* file, uint64_t length) {
    if ((file->flags & O_ACCMODE) == O_RDONLY)
        return -EINVAL;
    return inode_truncate(file->filemap->inode, length);
}

int file_sync(struct file* file, uint64_t offset, uint64_t nbytes) {
    return inode_sync(file->filemap->inode, offset, nbytes);
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
        mutex_lock(&file->lock);
        file->offset = offset;
        mutex_unlock(&file->lock);
        return offset;
    case SEEK_CUR:
        mutex_lock(&file->lock);
        loff_t new_offset = (loff_t)file->offset + offset;
        if (new_offset < 0) {
            mutex_unlock(&file->lock);
            return -EINVAL;
        }
        file->offset = new_offset;
        mutex_unlock(&file->lock);
        return new_offset;
    case SEEK_END: {
        inode_lock(inode);
        loff_t size = (loff_t)inode->size;
        loff_t new_offset = size + offset;
        if (size < 0 || new_offset < 0) {
            inode_unlock(inode);
            return -EINVAL;
        }
        mutex_lock(&file->lock);
        file->offset = new_offset;
        mutex_unlock(&file->lock);
        inode_unlock(inode);
        return new_offset;
    }
    default:
        return -EINVAL;
    }
}

ssize_t file_readlink(struct file* file, char* buffer, size_t bufsiz) {
    if (!S_ISLNK(file->inode->mode))
        return -EINVAL;

    bufsiz = MIN(bufsiz, SYMLINK_MAX);

    if (file->fops->readlink)
        return file->fops->readlink(file, buffer, bufsiz);

    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;
    inode_lock(inode);

    struct page* page = filemap_ensure_page(filemap, 0, false);
    if (IS_ERR(page)) {
        inode_unlock(inode);
        return PTR_ERR(page);
    }
    if (!page) {
        inode_unlock(inode);
        return -EINVAL;
    }

    STATIC_ASSERT(SYMLINK_MAX <= PAGE_SIZE);

    char page_buf[PAGE_SIZE];
    page_copy_to_buffer(page, page_buf, 0, bufsiz);

    inode_unlock(inode);

    size_t len = strnlen(page_buf, bufsiz);
    memcpy(buffer, page_buf, len);
    return len;
}

int file_symlink(struct file* file, const char* target) {
    if (!S_ISLNK(file->inode->mode))
        return -EINVAL;

    STATIC_ASSERT(SYMLINK_MAX <= PAGE_SIZE);

    size_t len = strnlen(target, SYMLINK_MAX + 1);
    if (len > SYMLINK_MAX)
        return -ENAMETOOLONG;

    int rc = file_truncate(file, len);
    if (IS_ERR(rc))
        return rc;

    struct filemap* filemap = file->filemap;
    struct inode* inode = filemap->inode;
    inode_lock(inode);

    struct page* page = filemap_ensure_page(filemap, 0, true);
    if (IS_ERR(ASSERT(page))) {
        inode_unlock(inode);
        return PTR_ERR(page);
    }

    bool int_flag = push_cli();
    unsigned char* mapped_page = kmap_page(page);
    memcpy(mapped_page, target, len);
    memset(mapped_page + len, 0, PAGE_SIZE - len);
    kunmap(mapped_page);
    pop_cli(int_flag);

    page->flags |= PAGE_DIRTY;
    inode->flags |= INODE_DIRTY;

    inode_unlock(inode);
    return 0;
}

int file_ioctl(struct file* file, unsigned cmd, unsigned long arg) {
    if (!file->fops->ioctl)
        return -ENOTTY;
    return file->fops->ioctl(file, cmd, arg);
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

struct vm_obj* file_mmap(struct file* file) {
    if (file->fops->mmap)
        return file->fops->mmap(file);
    return vm_obj_ref(&file->filemap->inode->vm_obj);
}

int file_block(struct file* file, bool (*unblock)(struct file*), int flags) {
    if ((file->flags & O_NONBLOCK) && !unblock(file))
        return -EAGAIN;
    return sched_block((unblock_fn)unblock, file, flags);
}
