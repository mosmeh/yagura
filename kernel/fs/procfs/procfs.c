#include "procfs_private.h"
#include <kernel/fs/dentry.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/vec.h>

static void procfs_item_destroy_inode(struct inode* inode) { kfree(inode); }

static int procfs_item_open(file_description* desc, mode_t mode) {
    (void)mode;

    struct vec* vec = kmalloc(sizeof(struct vec));
    if (!vec)
        return -ENOMEM;
    *vec = (struct vec){0};

    procfs_item_inode* node = (procfs_item_inode*)desc->inode;
    int rc = node->populate(desc, vec);
    if (IS_ERR(rc)) {
        kfree(vec);
        return rc;
    }

    desc->private_data = vec;
    return 0;
}

static int procfs_item_close(file_description* desc) {
    vec_destroy(desc->private_data);
    kfree(desc->private_data);
    return 0;
}

static ssize_t procfs_item_read(file_description* desc, void* buffer,
                                size_t count) {
    mutex_lock(&desc->offset_lock);
    ssize_t nread = vec_pread(desc->private_data, buffer, count, desc->offset);
    if (IS_OK(nread))
        desc->offset += nread;
    mutex_unlock(&desc->offset_lock);
    return nread;
}

file_ops procfs_item_fops = {.destroy_inode = procfs_item_destroy_inode,
                             .open = procfs_item_open,
                             .close = procfs_item_close,
                             .read = procfs_item_read};

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

int procfs_dir_getdents(file_description* desc, getdents_callback_fn callback,
                        void* ctx) {
    procfs_dir_inode* node = (procfs_dir_inode*)desc->inode;
    mutex_lock(&desc->offset_lock);
    int rc = dentry_getdents(desc, node->children, callback, ctx);
    mutex_unlock(&desc->offset_lock);
    return rc;
}
