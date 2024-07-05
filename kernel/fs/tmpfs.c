#include "dentry.h"
#include <kernel/api/sys/sysmacros.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/vec.h>

typedef struct tmpfs_inode {
    struct inode inode;
    mutex lock;
    struct vec content;
    struct dentry* children;
} tmpfs_inode;

static void tmpfs_destroy_inode(struct inode* inode) {
    tmpfs_inode* node = (tmpfs_inode*)inode;
    vec_destroy(&node->content);
    dentry_clear(node->children);
    kfree(node);
}

static struct inode* tmpfs_lookup_child(struct inode* inode, const char* name) {
    tmpfs_inode* node = (tmpfs_inode*)inode;
    mutex_lock(&node->lock);
    struct inode* child = dentry_find(node->children, name);
    mutex_unlock(&node->lock);
    inode_unref(inode);
    return child;
}

static int tmpfs_stat(struct inode* inode, struct stat* buf) {
    tmpfs_inode* node = (tmpfs_inode*)inode;
    buf->st_size = node->content.size;
    inode_unref(inode);
    return 0;
}

static ssize_t tmpfs_read(file_description* desc, void* buffer, size_t count) {
    tmpfs_inode* node = (tmpfs_inode*)desc->inode;
    mutex_lock(&desc->offset_lock);
    mutex_lock(&node->lock);
    ssize_t nread = vec_pread(&node->content, buffer, count, desc->offset);
    mutex_unlock(&node->lock);
    if (IS_OK(nread))
        desc->offset += nread;
    mutex_unlock(&desc->offset_lock);
    return nread;
}

static ssize_t tmpfs_write(file_description* desc, const void* buffer,
                           size_t count) {
    tmpfs_inode* node = (tmpfs_inode*)desc->inode;
    mutex_lock(&desc->offset_lock);
    mutex_lock(&node->lock);
    ssize_t nwritten = vec_pwrite(&node->content, buffer, count, desc->offset);
    mutex_unlock(&node->lock);
    if (IS_OK(nwritten))
        desc->offset += nwritten;
    mutex_unlock(&desc->offset_lock);
    return nwritten;
}

static void* tmpfs_mmap(file_description* desc, size_t length, off_t offset,
                        int flags) {
    tmpfs_inode* node = (tmpfs_inode*)desc->inode;
    mutex_lock(&node->lock);
    void* ret = vec_mmap(&node->content, length, offset, flags);
    mutex_unlock(&node->lock);
    return ret;
}

static int tmpfs_truncate(file_description* desc, off_t length) {
    tmpfs_inode* node = (tmpfs_inode*)desc->inode;
    mutex_lock(&node->lock);
    int rc = vec_resize(&node->content, length);
    mutex_unlock(&node->lock);
    return rc;
}

static int tmpfs_getdents(file_description* desc, getdents_callback_fn callback,
                          void* ctx) {
    tmpfs_inode* node = (tmpfs_inode*)desc->inode;
    mutex_lock(&node->lock);
    mutex_lock(&desc->offset_lock);
    int rc = dentry_getdents(desc, node->children, callback, ctx);
    mutex_unlock(&desc->offset_lock);
    mutex_unlock(&node->lock);
    return rc;
}

static int tmpfs_link_child(struct inode* inode, const char* name,
                            struct inode* child) {
    tmpfs_inode* node = (tmpfs_inode*)inode;
    mutex_lock(&node->lock);
    int rc = dentry_append(&node->children, name, child);
    mutex_unlock(&node->lock);
    inode_unref(inode);
    return rc;
}

static struct inode* tmpfs_unlink_child(struct inode* inode, const char* name) {
    tmpfs_inode* node = (tmpfs_inode*)inode;
    mutex_lock(&node->lock);
    struct inode* child = dentry_remove(&node->children, name);
    mutex_unlock(&node->lock);
    inode_unref(inode);
    return child;
}

static struct inode* tmpfs_create_child(struct inode* inode, const char* name,
                                        mode_t mode);

static file_ops dir_fops = {
    .destroy_inode = tmpfs_destroy_inode,
    .lookup_child = tmpfs_lookup_child,
    .create_child = tmpfs_create_child,
    .link_child = tmpfs_link_child,
    .unlink_child = tmpfs_unlink_child,
    .stat = tmpfs_stat,
    .getdents = tmpfs_getdents,
};
static file_ops non_dir_fops = {
    .destroy_inode = tmpfs_destroy_inode,
    .stat = tmpfs_stat,
    .read = tmpfs_read,
    .write = tmpfs_write,
    .mmap = tmpfs_mmap,
    .truncate = tmpfs_truncate,
};

static struct inode* tmpfs_create_child(struct inode* inode, const char* name,
                                        mode_t mode) {
    tmpfs_inode* child = kmalloc(sizeof(tmpfs_inode));
    if (!child)
        return ERR_PTR(-ENOMEM);
    *child = (tmpfs_inode){0};

    struct inode* child_inode = &child->inode;
    child_inode->dev = inode->dev;
    child_inode->fops = S_ISDIR(mode) ? &dir_fops : &non_dir_fops;
    child_inode->mode = mode;
    child_inode->ref_count = 1;

    inode_ref(child_inode);
    int rc = tmpfs_link_child(inode, name, child_inode);
    if (IS_ERR(rc)) {
        inode_unref(child_inode);
        return ERR_PTR(rc);
    }

    return child_inode;
}

struct inode* tmpfs_create_root(void) {
    tmpfs_inode* root = kmalloc(sizeof(tmpfs_inode));
    if (!root)
        return ERR_PTR(-ENOMEM);
    *root = (tmpfs_inode){0};

    struct inode* inode = &root->inode;
    inode->dev = vfs_generate_unnamed_device_number();
    inode->fops = &dir_fops;
    inode->mode = S_IFDIR;
    inode->ref_count = 1;

    return inode;
}
