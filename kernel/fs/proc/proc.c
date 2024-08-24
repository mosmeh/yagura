#include "private.h"
#include <kernel/containers/vec.h>
#include <kernel/fs/dentry.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

static void proc_item_destroy_inode(struct inode* inode) { kfree(inode); }

static int proc_item_open(struct file* file, mode_t mode) {
    (void)mode;

    struct vec* vec = kmalloc(sizeof(struct vec));
    if (!vec)
        return -ENOMEM;
    *vec = (struct vec){0};

    proc_item_inode* node = (proc_item_inode*)file->inode;
    int rc = node->populate(file, vec);
    if (IS_ERR(rc)) {
        vec_destroy(vec);
        kfree(vec);
        return rc;
    }

    file->private_data = vec;
    return 0;
}

static int proc_item_close(struct file* file) {
    vec_destroy(file->private_data);
    kfree(file->private_data);
    return 0;
}

static ssize_t proc_item_read(struct file* file, void* buffer, size_t count) {
    mutex_lock(&file->offset_lock);
    ssize_t nread = vec_pread(file->private_data, buffer, count, file->offset);
    if (IS_OK(nread))
        file->offset += nread;
    mutex_unlock(&file->offset_lock);
    return nread;
}

const struct file_ops proc_item_fops = {
    .destroy_inode = proc_item_destroy_inode,
    .open = proc_item_open,
    .close = proc_item_close,
    .read = proc_item_read,
};

void proc_dir_destroy_inode(struct inode* inode) {
    proc_dir_inode* node = (proc_dir_inode*)inode;
    dentry_clear(node->children);
    kfree(node);
}

struct inode* proc_dir_lookup_child(struct inode* inode, const char* name) {
    proc_dir_inode* node = (proc_dir_inode*)inode;
    struct inode* child = dentry_find(node->children, name);
    inode_unref(inode);
    return child;
}

int proc_dir_getdents(struct file* file, getdents_callback_fn callback,
                      void* ctx) {
    proc_dir_inode* node = (proc_dir_inode*)file->inode;
    mutex_lock(&file->offset_lock);
    int rc = dentry_getdents(file, node->children, callback, ctx);
    mutex_unlock(&file->offset_lock);
    return rc;
}

void proc_init(void) {
    static struct file_system fs = {
        .name = "proc",
        .mount = proc_mount,
    };
    ASSERT_OK(vfs_register_file_system(&fs));
}
