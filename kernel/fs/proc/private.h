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

extern const struct file_ops proc_item_fops;

typedef struct {
    struct inode inode;
    struct dentry* children;
} proc_dir_inode;

void proc_dir_destroy_inode(struct inode* inode);
struct inode* proc_dir_lookup_child(struct inode* inode, const char* name);
int proc_dir_getdents(struct file*, getdents_callback_fn callback, void* ctx);

struct inode* proc_pid_dir_inode_create(proc_dir_inode* parent, pid_t pid);
