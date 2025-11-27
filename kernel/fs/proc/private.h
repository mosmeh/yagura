#pragma once

#include <kernel/fs/fs.h>
#include <kernel/fs/private.h>

#define PROC_ROOT_INO 1
#define PROC_PID_INO_SHIFT 10

struct proc_entry {
    const char* name;
    mode_t mode;
    proc_print_fn print;
};

struct inode* proc_create_inode(struct mount*, ino_t, struct proc_entry*);
struct inode* proc_lookup(struct inode* parent, const char* name,
                          struct proc_entry* entries, size_t num_entries);
int proc_getdents(struct file*, getdents_callback_fn, void* ctx,
                  const struct proc_entry* entries, size_t num_entries);

struct inode* proc_root_lookup(struct inode* parent, const char* name);
int proc_root_getdents(struct file*, getdents_callback_fn, void* ctx);

struct inode* proc_pid_lookup(struct inode* parent, const char* name);
int proc_pid_getdents(struct file*, getdents_callback_fn, void* ctx);
