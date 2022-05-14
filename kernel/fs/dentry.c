#include "dentry.h"
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/err.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

struct inode* dentry_find(const struct dentry* head, const char* name) {
    const struct dentry* dentry = head;
    while (dentry) {
        if (!strcmp(dentry->name, name)) {
            inode_ref(dentry->inode);
            return dentry->inode;
        }
        dentry = dentry->next;
    }
    return ERR_PTR(-ENOENT);
}

long dentry_readdir(const struct dentry* head, void* dirp, unsigned int count,
                    off_t* out_offset) {
    ASSERT(out_offset);

    const struct dentry* dentry = head;
    if (!dentry)
        return 0;

    for (off_t i = 0; i < *out_offset; ++i) {
        dentry = dentry->next;
        if (!dentry)
            return 0;
    }

    uintptr_t buf = (uintptr_t)dirp;
    long nread = 0;

    while (count > 0 && dentry) {
        size_t name_len = strlen(dentry->name);
        size_t name_size = name_len + 1;
        size_t size = offsetof(struct dirent, d_name) + name_size;
        if (count < size)
            break;

        struct dirent* dent = (struct dirent*)buf;
        dent->d_type = mode_to_dirent_type(dentry->inode->mode);
        dent->d_reclen = size;
        dent->d_namlen = name_len;
        strlcpy(dent->d_name, dentry->name, name_size);

        ++*out_offset;
        dentry = dentry->next;
        nread += size;
        buf += size;
        count -= size;
    }

    if (nread == 0)
        return -EINVAL;
    return nread;
}

int dentry_append(struct dentry** head, const char* name, struct inode* child) {
    struct dentry* prev = NULL;
    struct dentry* it = *head;
    while (it) {
        if (!strcmp(it->name, name))
            return -EEXIST;
        prev = it;
        it = it->next;
    }

    struct dentry* new_dentry = kmalloc(sizeof(struct dentry));
    if (!new_dentry)
        return -ENOMEM;
    *new_dentry = (struct dentry){0};

    new_dentry->name = kstrdup(name);
    if (!new_dentry->name)
        return -ENOMEM;
    new_dentry->inode = child;

    if (prev)
        prev->next = new_dentry;
    else
        *head = new_dentry;

    return 0;
}

struct inode* dentry_remove(struct dentry** head, const char* name) {
    struct dentry* prev = NULL;
    struct dentry* it = *head;
    while (it) {
        if (!strcmp(it->name, name)) {
            if (prev)
                prev->next = it->next;
            else
                *head = it->next;
            struct inode* inode = it->inode;
            kfree(it);
            return inode;
        }
        prev = it;
        it = it->next;
    }
    return ERR_PTR(-ENOENT);
}
