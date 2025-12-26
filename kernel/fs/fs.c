#include "private.h"
#include <common/integer.h>
#include <kernel/api/fcntl.h>
#include <kernel/device/device.h>
#include <kernel/fs/file.h>

void fs_init(const multiboot_module_t* initrd_mod) {
    file_init();
    path_init();
    filemap_init();
    vfs_init(initrd_mod);
    pipe_init();
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

    struct file* file FREE(file) = file_create(inode, flags);
    if (IS_ERR(ASSERT(file)))
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
