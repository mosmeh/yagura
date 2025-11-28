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

    char* basename FREE(kfree) = NULL;
    if (path->basename) {
        basename = kstrdup(path->basename);
        if (!basename)
            return ERR_PTR(-ENOMEM);
    }

    struct path* parent FREE(path) = path_dup(path->parent);
    if (IS_ERR(parent))
        return parent;

    struct path* new_path = kmalloc(sizeof(struct path));
    if (!new_path)
        return ERR_PTR(-ENOMEM);
    *new_path = (struct path){
        .inode = inode_ref(path->inode),
        .basename = TAKE_PTR(basename),
        .parent = TAKE_PTR(parent),
    };
    return new_path;
}

struct path* path_join(struct path* parent, struct inode* inode,
                       const char* basename) {
    struct path* dup_parent FREE(path) = path_dup(parent);
    if (IS_ERR(dup_parent))
        return dup_parent;

    char* dup_basename FREE(kfree) = kstrdup(basename);
    if (!basename)
        return ERR_PTR(-ENOMEM);

    struct path* path = kmalloc(sizeof(struct path));
    if (!path)
        return ERR_PTR(-ENOMEM);

    if (inode)
        inode_ref(inode);
    *path = (struct path){
        .inode = inode,
        .basename = TAKE_PTR(dup_basename),
        .parent = TAKE_PTR(dup_parent),
    };
    return path;
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
