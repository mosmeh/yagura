#include "private.h"
#include <common/integer.h>
#include <kernel/api/fcntl.h>
#include <kernel/device/block.h>
#include <kernel/device/char.h>
#include <kernel/fs/file.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/vfs.h>
#include <kernel/memory/phys.h>

static void inode_destroy(struct vm_obj* obj) {
    struct inode* inode = CONTAINER_OF(obj, struct inode, vm_obj);
    ASSERT_PTR(inode->iops->destroy);
    filemap_destroy(inode->filemap);
    inode_unref(inode->pipe);
    inode_unref(inode->bound_socket);
    inode->iops->destroy(inode);
}

static struct page* inode_get_page(struct vm_obj* obj, size_t index,
                                   unsigned request) {
    struct inode* inode = CONTAINER_OF(obj, struct inode, vm_obj);
    bool write = request & VM_WRITE;
    if (write && !inode->iops->write)
        return ERR_PTR(-EINVAL);

    SCOPED_LOCK(inode, inode);

    if (((uint64_t)index << PAGE_SHIFT) >= inode->size)
        return NULL;

    struct page* page = ASSERT(filemap_ensure_page(inode->filemap, index));
    if (IS_ERR(page))
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

    SCOPED_LOCK(inode, inode);
    return filemap_sync(inode->filemap, start, end);
}

int inode_truncate(struct inode* inode, uint64_t length) {
    if (!inode->iops->truncate)
        return -EINVAL;
    if (S_ISDIR(inode->mode))
        return -EISDIR;

    SCOPED_LOCK(inode, inode);

    uint64_t old_size = inode->size;
    if (old_size == length)
        return 0;

    int rc = inode->iops->truncate(inode, length);
    if (IS_ERR(rc))
        return rc;

    inode->size = length;
    inode->flags |= INODE_DIRTY;

    if (length < old_size)
        return filemap_truncate(inode->filemap, length);

    return 0;
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

    struct file* file FREE(file) = ASSERT(file_create(inode, flags));
    if (IS_ERR(file))
        return file;

    switch (inode->mode & S_IFMT) {
    case S_IFCHR:
        file->fops = &char_dev_fops;
        break;
    case S_IFBLK:
        file->fops = &block_dev_fops;
        break;
    case S_IFIFO:
        file->fops = &pipe_fops;
        break;
    }

    static const struct file_ops null_fops = {0};
    if (file->fops->open) {
        int rc = file->fops->open(file);
        if (IS_ERR(rc)) {
            file->fops = &null_fops; // Remove fops to avoid calling close().
            return ERR_PTR(rc);
        }
    }

    if (flags & O_TRUNC) {
        if (S_ISDIR(inode->mode))
            return ERR_PTR(-EISDIR);
        // Truncation is performed even with O_RDONLY.
        if (inode->iops->truncate) {
            int rc = inode_truncate(inode, 0);
            if (IS_ERR(rc))
                return ERR_PTR(rc);
        }
    }

    return TAKE_PTR(file);
}

int inode_stat(struct inode* inode, struct kstat* buf) {
    SCOPED_LOCK(inode, inode);
    *buf = (struct kstat){
        .st_ino = inode->ino,
        .st_dev = inode->mount->dev,
        .st_mode = inode->mode,
        .st_uid = inode->uid,
        .st_gid = inode->gid,
        .st_rdev = inode->rdev,
        .st_size = inode->size,
        .st_blksize = 1 << inode->block_bits,
        .st_blocks = inode->blocks,
    };
    return 0;
}
