#include "path.h"
#include "fs.h"
#include <common/string.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

char* path_to_string(const struct path* path) {
    if (!path->parent) // Root directory
        return kstrdup(ROOT_DIR);

    size_t len = 1; // For the null terminator
    for (const struct path* it = path; it; it = it->parent) {
        if (it->basename)
            len += strlen(it->basename) + 1; // +1 for the '/'
        else
            ASSERT(it->parent == NULL); // Root directory
    }
    char* s = kmalloc(len);
    if (!s)
        return NULL;
    char* p = s + len - 1;
    *p = 0;
    for (const struct path* it = path; it; it = it->parent) {
        if (!it->basename) {
            ASSERT(it->parent == NULL); // Root directory
            break;
        }
        size_t basename_len = strlen(it->basename);
        p -= basename_len;
        memcpy(p, it->basename, basename_len);
        --p;
        *p = PATH_SEPARATOR;
    }
    ASSERT(p == s);
    return s;
}

struct path* path_dup(const struct path* path) {
    if (!path)
        return NULL;
    struct path* new_path = kmalloc(sizeof(struct path));
    if (!new_path)
        return ERR_PTR(-ENOMEM);
    *new_path = (struct path){0};
    if (path->basename) {
        new_path->basename = kstrdup(path->basename);
        if (!new_path->basename) {
            kfree(new_path);
            return ERR_PTR(-ENOMEM);
        }
    }
    new_path->parent = path_dup(path->parent);
    if (IS_ERR(new_path->parent)) {
        kfree(new_path->basename);
        kfree(new_path);
        return new_path->parent;
    }
    new_path->inode = path->inode;
    inode_ref(new_path->inode);
    return new_path;
}

struct path* path_join(struct path* parent, struct inode* inode,
                       const char* basename) {
    struct path* path = kmalloc(sizeof(struct path));
    if (!path) {
        inode_unref(inode);
        return ERR_PTR(-ENOMEM);
    }
    path->basename = kstrdup(basename);
    if (!path->basename) {
        kfree(path);
        inode_unref(inode);
        return ERR_PTR(-ENOMEM);
    }
    path->inode = inode;
    path->parent = parent;
    return path;
}

struct inode* path_into_inode(struct path* path) {
    if (!path)
        return NULL;
    struct inode* inode = path->inode;
    path->inode = NULL;
    path_destroy_recursive(path);
    return inode;
}

void path_destroy_last(struct path* path) {
    if (!path)
        return;
    inode_unref(path->inode);
    kfree(path->basename);
    kfree(path);
}

void path_destroy_recursive(struct path* path) {
    while (path) {
        struct path* parent = path->parent;
        path_destroy_last(path);
        path = parent;
    }
}
