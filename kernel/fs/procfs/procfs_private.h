#pragma once

#include <kernel/fs/fs.h>
#include <kernel/growable_buf.h>

typedef struct growable_buf growable_buf;

typedef int (*procfs_populate_fn)(file_description*, growable_buf*);

typedef struct procfs_item_def {
    const char* name;
    mode_t mode;
    procfs_populate_fn populate;
} procfs_item_def;

typedef struct procfs_item_inode {
    struct inode inode;
    procfs_populate_fn populate;
} procfs_item_inode;

extern file_ops procfs_item_fops;

typedef struct procfs_dir_inode {
    struct inode inode;
    struct dentry* children;
} procfs_dir_inode;

void procfs_dir_destroy_inode(struct inode* inode);
struct inode* procfs_dir_lookup_child(struct inode* inode, const char* name);
int procfs_dir_getdents(file_description* desc, getdents_callback_fn callback,
                        void* ctx);

struct inode* procfs_pid_dir_inode_create(procfs_dir_inode* parent, pid_t pid);
