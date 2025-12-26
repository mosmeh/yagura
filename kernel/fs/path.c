#include "private.h"
#include <common/string.h>
#include <kernel/fs/fs.h>
#include <kernel/fs/path.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/task.h>

static struct slab path_slab;

void path_init(void) { slab_init(&path_slab, "path", sizeof(struct path)); }

struct path* path_create_root(struct inode* root) {
    struct path* path = slab_alloc(&path_slab);
    if (IS_ERR(path))
        return path;
    *path = (struct path){.inode = inode_ref(root)};
    return path;
}

char* path_to_string(const struct path* path) {
    if (!path->parent) // Root directory of the VFS
        return kstrdup(ROOT_DIR);

    struct inode* root_inode FREE(inode) = NULL;
    {
        struct fs* fs = current->fs;
        SCOPED_LOCK(fs, fs);
        root_inode = inode_ref(fs->root->inode);
    }

    if (path->inode == root_inode) // Root directory of the chroot
        return kstrdup(ROOT_DIR);

    size_t len = 1; // For the null terminator
    for (const struct path* it = path; it; it = it->parent) {
        if (it->inode == root_inode)
            break;
        if (it->basename)
            len += strlen(it->basename) + 1; // +1 for the '/'
        else
            ASSERT(it->parent == NULL); // Root directory of the VFS
    }
    char* s = kmalloc(len);
    if (!s)
        return NULL;
    char* p = s + len - 1;
    *p = 0;
    for (const struct path* it = path; it; it = it->parent) {
        if (it->inode == root_inode)
            break;
        if (!it->basename) {
            ASSERT(it->parent == NULL); // Root directory of the VFS
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

    struct path* new_path = slab_alloc(&path_slab);
    if (IS_ERR(new_path))
        return new_path;
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

    struct path* path = slab_alloc(&path_slab);
    if (IS_ERR(path))
        return path;

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
    slab_free(&path_slab, path);
}

void path_destroy_recursive(struct path* path) {
    while (path) {
        struct path* parent = path->parent;
        path_destroy_last(path);
        path = parent;
    }
}
