#include "dentry.h"
#include "fs.h"
#include <kernel/api/sys/stat.h>
#include <kernel/growable_buf.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/system.h>

typedef struct procfs_root_inode {
    struct inode inode;
    struct dentry* children;
} procfs_root_inode;

static struct inode* procfs_root_lookup_child(struct inode* inode,
                                              const char* name) {
    procfs_root_inode* node = (procfs_root_inode*)inode;
    struct inode* child = dentry_find(node->children, name);
    inode_unref(inode);
    return child;
}

static long procfs_root_readdir(file_description* desc, void* dirp,
                                unsigned int count) {
    procfs_root_inode* node = (procfs_root_inode*)desc->inode;
    mutex_lock(&desc->offset_lock);
    long rc = dentry_readdir(node->children, dirp, count, &desc->offset);
    mutex_unlock(&desc->offset_lock);
    return rc;
}

typedef int (*populate_buf_fn)(growable_buf*);

typedef struct procfs_item_inode {
    struct inode inode;
    populate_buf_fn populate_buf;
} procfs_item_inode;

static int procfs_item_open(file_description* desc, int flags, mode_t mode) {
    (void)flags;
    (void)mode;

    growable_buf* buf = kmalloc(sizeof(growable_buf));
    if (!buf)
        return -ENOMEM;
    *buf = (growable_buf){0};

    procfs_item_inode* node = (procfs_item_inode*)desc->inode;
    int rc = node->populate_buf(buf);
    if (IS_ERR(rc)) {
        kfree(buf);
        return rc;
    }

    desc->private_data = buf;
    return 0;
}

static int procfs_item_close(file_description* desc) {
    growable_buf_destroy(desc->private_data);
    kfree(desc->private_data);
    return 0;
}

static ssize_t procfs_item_read(file_description* desc, void* buffer,
                                size_t count) {
    mutex_lock(&desc->offset_lock);
    ssize_t nread =
        growable_buf_pread(desc->private_data, buffer, count, desc->offset);
    if (IS_OK(nread))
        desc->offset += nread;
    mutex_unlock(&desc->offset_lock);
    return nread;
}

static int add_item(procfs_root_inode* root, const char* name,
                    populate_buf_fn populate_buf) {
    procfs_item_inode* node = kmalloc(sizeof(procfs_item_inode));
    if (!node)
        return -ENOMEM;
    *node = (procfs_item_inode){0};

    node->populate_buf = populate_buf;

    static file_ops fops = {.open = procfs_item_open,
                            .close = procfs_item_close,
                            .read = procfs_item_read};
    struct inode* inode = &node->inode;
    inode->fs_root_inode = &root->inode;
    inode->fops = &fops;
    inode->mode = S_IFREG;
    inode->num_links = inode->ref_count = 1;

    return dentry_append(&root->children, name, inode);
}

static int populate_cmdline(growable_buf* buf) {
    return growable_buf_printf(buf, "%s\n", cmdline_get_raw());
}

struct inode* procfs_create_root(void) {
    procfs_root_inode* root = kmalloc(sizeof(procfs_root_inode));
    if (!root)
        return ERR_PTR(-ENOMEM);
    *root = (procfs_root_inode){0};

    int rc = add_item(root, "cmdline", populate_cmdline);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    static file_ops fops = {
        .lookup_child = procfs_root_lookup_child,
        .readdir = procfs_root_readdir,
    };

    struct inode* inode = &root->inode;
    inode->fs_root_inode = inode;
    inode->fops = &fops;
    inode->mode = S_IFDIR;
    inode->ref_count = 1;

    return inode;
}