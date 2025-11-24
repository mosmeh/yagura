#include "dentry.h"
#include "fs.h"
#include <kernel/api/sys/sysmacros.h>
#include <kernel/containers/vec.h>
#include <kernel/device/device.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

typedef struct {
    struct inode inode;
    struct dentry* children;
} tmpfs_inode;

static void tmpfs_destroy(struct inode* inode) {
    tmpfs_inode* node = CONTAINER_OF(inode, tmpfs_inode, inode);
    dentry_clear(node->children);
    kfree(node);
}

static struct inode* tmpfs_lookup(struct inode* parent, const char* name) {
    tmpfs_inode* node = CONTAINER_OF(parent, tmpfs_inode, inode);
    mutex_lock(&parent->lock);
    struct inode* child = dentry_find(node->children, name);
    mutex_unlock(&parent->lock);
    inode_unref(parent);
    return child;
}

static int tmpfs_link(struct inode* parent, const char* name,
                      struct inode* child) {
    tmpfs_inode* node = CONTAINER_OF(parent, tmpfs_inode, inode);
    mutex_lock(&parent->lock);
    int rc = dentry_append(&node->children, name, child);
    mutex_unlock(&parent->lock);
    inode_unref(parent);
    return rc;
}

static int tmpfs_unlink(struct inode* parent, const char* name) {
    tmpfs_inode* node = CONTAINER_OF(parent, tmpfs_inode, inode);
    mutex_lock(&parent->lock);
    struct inode* child = dentry_remove(&node->children, name);
    mutex_unlock(&parent->lock);
    inode_unref(parent);
    inode_unref(child);
    return 0;
}

static int tmpfs_getdents(struct file* file, getdents_callback_fn callback,
                          void* ctx) {
    struct inode* inode = file->inode;
    tmpfs_inode* node = CONTAINER_OF(inode, tmpfs_inode, inode);
    mutex_lock(&inode->lock);
    file_lock(file);
    int rc = dentry_getdents(file, node->children, callback, ctx);
    file_unlock(file);
    mutex_unlock(&inode->lock);
    return rc;
}

static struct inode* tmpfs_create(struct inode* parent, const char* name,
                                  mode_t mode);

// This is called only when populating the page cache.
// Since tmpfs is empty when created, we can just return no data.
static ssize_t tmpfs_pread(struct inode* inode, void* buffer, size_t count,
                           uint64_t offset) {
    (void)inode;
    (void)buffer;
    (void)count;
    (void)offset;
    return 0;
}

// The page cache stores the actual data, so we don't need to do anything here.
static ssize_t tmpfs_pwrite(struct inode* inode, const void* buffer,
                            size_t count, uint64_t offset) {
    (void)inode;
    (void)buffer;
    (void)offset;
    return count;
}

// Truncating is handled by invalidating the page cache, so nothing to do here.
static int tmpfs_truncate(struct file* file, uint64_t length) {
    (void)file;
    (void)length;
    return 0;
}

static const struct inode_ops dir_iops = {
    .destroy = tmpfs_destroy,
    .lookup = tmpfs_lookup,
    .create = tmpfs_create,
    .link = tmpfs_link,
    .unlink = tmpfs_unlink,
};
static const struct file_ops dir_fops = {
    .getdents = tmpfs_getdents,
};
static const struct inode_ops file_iops = {
    .destroy = tmpfs_destroy,
    .pread = tmpfs_pread,
    .pwrite = tmpfs_pwrite,
};
static const struct file_ops file_fops = {
    .truncate = tmpfs_truncate,
};

static struct inode* tmpfs_create(struct inode* parent, const char* name,
                                  mode_t mode) {
    tmpfs_inode* child = kmalloc(sizeof(tmpfs_inode));
    if (!child)
        return ERR_PTR(-ENOMEM);
    *child = (tmpfs_inode){0};

    struct inode* child_inode = &child->inode;
    child_inode->dev = parent->dev;
    child_inode->iops = S_ISDIR(mode) ? &dir_iops : &file_iops;
    child_inode->fops = S_ISDIR(mode) ? &dir_fops : &file_fops;
    child_inode->mode = mode;
    child_inode->ref_count = 1;

    inode_ref(child_inode);
    int rc = tmpfs_link(parent, name, child_inode);
    if (IS_ERR(rc)) {
        inode_unref(child_inode);
        return ERR_PTR(rc);
    }

    return child_inode;
}

static struct inode* tmpfs_mount(const char* source) {
    (void)source;

    tmpfs_inode* root = kmalloc(sizeof(tmpfs_inode));
    if (!root)
        return ERR_PTR(-ENOMEM);
    *root = (tmpfs_inode){0};

    struct inode* inode = &root->inode;
    inode->dev = block_dev_generate_unnamed_device_number();
    inode->iops = &dir_iops;
    inode->fops = &dir_fops;
    inode->mode = S_IFDIR;
    inode->ref_count = 1;

    return inode;
}

void tmpfs_init(void) {
    static struct file_system fs = {
        .name = "tmpfs",
        .mount = tmpfs_mount,
    };
    ASSERT_OK(vfs_register_file_system(&fs));
}
