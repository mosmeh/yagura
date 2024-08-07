#pragma once

#include "fs.h"

struct dentry {
    char* name;
    struct inode* inode;
    struct dentry* next;
};

NODISCARD struct inode* dentry_find(const struct dentry* head,
                                    const char* name);
NODISCARD int dentry_getdents(struct file*, const struct dentry* head,
                              getdents_callback_fn callback, void* ctx);
NODISCARD int dentry_append(struct dentry** head, const char* name,
                            struct inode* child);
NODISCARD struct inode* dentry_remove(struct dentry** head, const char* name);
void dentry_clear(struct dentry* head);
