#pragma once

#include "fs.h"

struct dentry {
    char* name;
    struct inode* inode;
    struct dentry* next;
};

NODISCARD struct inode* dentry_find(const struct dentry* head,
                                    const char* name);
NODISCARD long dentry_readdir(const struct dentry* head, void* dirp,
                              unsigned int count, off_t* out_offset);
NODISCARD int dentry_append(struct dentry** head, const char* name,
                            struct inode* child);
NODISCARD struct inode* dentry_remove(struct dentry** head, const char* name);
