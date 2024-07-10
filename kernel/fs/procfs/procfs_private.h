#pragma once

#include <kernel/fs/fs.h>
#include <kernel/vec.h>

struct vec;

typedef int (*procfs_populate_fn)(struct file*, struct vec*);

typedef struct {
    const char* name;
    mode_t mode;
    procfs_populate_fn populate;
} procfs_item_def;

typedef struct {
    struct inode inode;
    procfs_populate_fn populate;
} procfs_item_inode;

extern struct file_ops procfs_item_fops;

typedef struct {
    struct inode inode;
    struct dentry* children;
} procfs_dir_inode;

void procfs_dir_destroy_inode(struct inode* inode);
struct inode* procfs_dir_lookup_child(struct inode* inode, const char* name);
int procfs_dir_getdents(struct file*, getdents_callback_fn callback, void* ctx);

struct inode* procfs_pid_dir_inode_create(procfs_dir_inode* parent, pid_t pid);
