#pragma once

#include <kernel/fs/fs.h>

struct vec;

struct inode* proc_mount(const char* source);

typedef int (*proc_populate_fn)(struct file*, struct vec*);

typedef struct {
    const char* name;
    mode_t mode;
    proc_populate_fn populate;
} proc_item_def;

typedef struct {
    struct inode inode;
    proc_populate_fn populate;
} proc_item_inode;

extern const struct inode_ops proc_item_iops;
extern const struct file_ops proc_item_fops;

typedef struct {
    struct inode inode;
    struct dentry* children;
} proc_dir_inode;

static inline proc_dir_inode* proc_dir_from_inode(struct inode* inode) {
    return CONTAINER_OF(inode, proc_dir_inode, inode);
}

void proc_dir_destroy(struct inode*);
struct inode* proc_dir_lookup(struct inode* parent, const char* name);
int proc_dir_getdents(struct file*, getdents_callback_fn callback, void* ctx);

struct inode* proc_pid_dir_inode_create(proc_dir_inode* parent, pid_t pid);
