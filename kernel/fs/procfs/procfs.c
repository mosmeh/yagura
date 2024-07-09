#include "procfs_private.h"
#include <kernel/fs/dentry.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/vec.h>

static void procfs_item_destroy_inode(struct inode* inode) { kfree(inode); }

static int procfs_item_open(struct file* file, mode_t mode) {
    (void)mode;

    struct vec* vec = kmalloc(sizeof(struct vec));
    if (!vec)
        return -ENOMEM;
    *vec = (struct vec){0};

    procfs_item_inode* node = (procfs_item_inode*)file->inode;
    int rc = node->populate(file, vec);
    if (IS_ERR(rc)) {
        vec_destroy(vec);
        kfree(vec);
        return rc;
    }

    file->private_data = vec;
    return 0;
}

static int procfs_item_close(struct file* file) {
    vec_destroy(file->private_data);
    kfree(file->private_data);
    return 0;
}

static ssize_t procfs_item_read(struct file* file, void* buffer, size_t count) {
    mutex_lock(&file->offset_lock);
    ssize_t nread = vec_pread(file->private_data, buffer, count, file->offset);
    if (IS_OK(nread))
        file->offset += nread;
    mutex_unlock(&file->offset_lock);
    return nread;
}

file_ops procfs_item_fops = {
    .destroy_inode = procfs_item_destroy_inode,
    .open = procfs_item_open,
    .close = procfs_item_close,
    .read = procfs_item_read,
};

void procfs_dir_destroy_inode(struct inode* inode) {
    procfs_dir_inode* node = (procfs_dir_inode*)inode;
    dentry_clear(node->children);
    kfree(node);
}

struct inode* procfs_dir_lookup_child(struct inode* inode, const char* name) {
    procfs_dir_inode* node = (procfs_dir_inode*)inode;
    struct inode* child = dentry_find(node->children, name);
    inode_unref(inode);
    return child;
}

int procfs_dir_getdents(struct file* file, getdents_callback_fn callback,
                        void* ctx) {
    procfs_dir_inode* node = (procfs_dir_inode*)file->inode;
    mutex_lock(&file->offset_lock);
    int rc = dentry_getdents(file, node->children, callback, ctx);
    mutex_unlock(&file->offset_lock);
    return rc;
}
