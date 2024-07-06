#include "procfs_private.h"
#include <common/string.h>
#include <kernel/api/sys/limits.h>
#include <kernel/fs/dentry.h>
#include <kernel/fs/path.h>
#include <kernel/interrupts.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/safe_string.h>
#include <kernel/vec.h>

typedef struct procfs_pid_item_inode {
    procfs_item_inode item_inode;
    pid_t pid;
} procfs_pid_item_inode;

static int populate_comm(file_description* desc, struct vec* vec) {
    procfs_pid_item_inode* node = (procfs_pid_item_inode*)desc->inode;
    struct process* process = process_find_process_by_pid(node->pid);
    if (!process)
        return -ENOENT;

    char comm[sizeof(process->comm)];
    strlcpy(comm, process->comm, sizeof(process->comm));

    process_unref(process);

    return vec_printf(vec, "%s\n", comm);
}

static int populate_cwd(file_description* desc, struct vec* vec) {
    procfs_pid_item_inode* node = (procfs_pid_item_inode*)desc->inode;
    struct process* process = process_find_process_by_pid(node->pid);
    if (!process)
        return -ENOENT;

    char* cwd = path_to_string(process->cwd);
    if (!cwd) {
        process_unref(process);
        return -ENOMEM;
    }

    int rc = vec_printf(vec, "%s", cwd);
    kfree(cwd);
    process_unref(process);
    return rc;
}

static int add_item(procfs_dir_inode* parent, const procfs_item_def* item_def,
                    pid_t pid) {
    procfs_pid_item_inode* node = kmalloc(sizeof(procfs_pid_item_inode));
    if (!node) {
        inode_unref((struct inode*)parent);
        return -ENOMEM;
    }
    *node = (procfs_pid_item_inode){0};

    node->pid = pid;
    node->item_inode.populate = item_def->populate;

    struct inode* inode = &node->item_inode.inode;
    inode->dev = parent->inode.dev;
    inode->fops = &procfs_item_fops;
    inode->mode = item_def->mode;
    inode->ref_count = 1;

    int rc = dentry_append(&parent->children, item_def->name, inode);
    inode_unref((struct inode*)parent);
    return rc;
}

static procfs_item_def pid_items[] = {
    {"comm", S_IFREG, populate_comm},
    {"cwd", S_IFLNK, populate_cwd},
};
#define NUM_ITEMS ARRAY_SIZE(pid_items)

struct inode* procfs_pid_dir_inode_create(procfs_dir_inode* parent, pid_t pid) {
    struct process* process = process_find_process_by_pid(pid);
    if (!process)
        return ERR_PTR(-ENOENT);
    process_unref(process);

    procfs_dir_inode* node = kmalloc(sizeof(procfs_dir_inode));
    if (!node)
        return ERR_PTR(-ENOMEM);
    *node = (procfs_dir_inode){0};

    static file_ops fops = {.destroy_inode = procfs_dir_destroy_inode,
                            .lookup_child = procfs_dir_lookup_child,
                            .getdents = procfs_dir_getdents};
    struct inode* inode = &node->inode;
    inode->dev = parent->inode.dev;
    inode->fops = &fops;
    inode->mode = S_IFDIR;
    inode->ref_count = 1;

    for (size_t i = 0; i < NUM_ITEMS; ++i) {
        inode_ref(inode);
        int rc = add_item(node, pid_items + i, pid);
        if (IS_ERR(rc))
            return ERR_PTR(rc);
    }

    inode_unref((struct inode*)parent);
    return inode;
}
