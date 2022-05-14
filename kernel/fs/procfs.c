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

static int procfs_root_getdents(struct getdents_ctx* ctx,
                                file_description* desc,
                                getdents_callback_fn callback) {
    procfs_root_inode* node = (procfs_root_inode*)desc->inode;
    mutex_lock(&desc->offset_lock);
    int rc = dentry_getdents(ctx, desc, node->children, callback);
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

static int populate_cmdline(growable_buf* buf) {
    return growable_buf_printf(buf, "%s\n", cmdline_get_raw());
}

static int populate_meminfo(growable_buf* buf) {
    struct physical_memory_info memory_info;
    page_allocator_get_info(&memory_info);

    return growable_buf_printf(buf,
                               "MemTotal: %8u kB\n"
                               "MemFree:  %8u kB\n",
                               memory_info.total, memory_info.free);
}

static int populate_uptime(growable_buf* buf) {
    return growable_buf_printf(buf, "%u\n", uptime / CLK_TCK);
}

struct procfs_item {
    const char* name;
    populate_buf_fn populate_buf;
};

static int add_item(procfs_root_inode* root, const struct procfs_item* item) {
    procfs_item_inode* node = kmalloc(sizeof(procfs_item_inode));
    if (!node)
        return -ENOMEM;
    *node = (procfs_item_inode){0};

    node->populate_buf = item->populate_buf;

    static file_ops fops = {.open = procfs_item_open,
                            .close = procfs_item_close,
                            .read = procfs_item_read};
    struct inode* inode = &node->inode;
    inode->fs_root_inode = &root->inode;
    inode->fops = &fops;
    inode->mode = S_IFREG;
    inode->ref_count = 1;

    return dentry_append(&root->children, item->name, inode);
}

static struct procfs_item root_items[] = {{"cmdline", populate_cmdline},
                                          {"meminfo", populate_meminfo},
                                          {"uptime", populate_uptime}};
#define NUM_ROOT_ITEMS (sizeof(root_items) / sizeof(struct procfs_item))

struct inode* procfs_create_root(void) {
    procfs_root_inode* root = kmalloc(sizeof(procfs_root_inode));
    if (!root)
        return ERR_PTR(-ENOMEM);
    *root = (procfs_root_inode){0};

    for (size_t i = 0; i < NUM_ROOT_ITEMS; ++i) {
        int rc = add_item(root, root_items + i);
        if (IS_ERR(rc))
            return ERR_PTR(rc);
    }

    static file_ops fops = {
        .lookup_child = procfs_root_lookup_child,
        .getdents = procfs_root_getdents,
    };

    struct inode* inode = &root->inode;
    inode->fs_root_inode = inode;
    inode->fops = &fops;
    inode->mode = S_IFDIR;
    inode->ref_count = 1;

    return inode;
}
