#include "fs.h"
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/kmalloc.h>
#include <kernel/kprintf.h>
#include <kernel/panic.h>
#include <stdbool.h>

typedef struct vfs_node {
    char* name;
    fs_node* fs;
    struct vfs_node* first_child;
    struct vfs_node* next_sibling;
} vfs_node;

static vfs_node root;

static vfs_node* find_child_by_name(vfs_node* node, const char* name) {
    vfs_node* child = node->first_child;
    if (!child)
        return NULL;

    for (;;) {
        if (!strcmp(child->name, name))
            return child;

        if (!child->next_sibling)
            return NULL;

        child = child->next_sibling;
    }
}

static void append_child(vfs_node* node, vfs_node* new_child) {
    new_child->next_sibling = NULL;

    if (!node->first_child) {
        node->first_child = new_child;
        return;
    }

    vfs_node* child = node->first_child;
    while (child->next_sibling)
        child = child->next_sibling;
    child->next_sibling = new_child;
}

void vfs_init(void) { root.name = "(root)"; }

static bool is_absolute_path(const char* path) {
    return path[0] == PATH_SEPARATOR;
}

void vfs_mount(const char* path, fs_node* fs) {
    KASSERT(is_absolute_path(path));

    size_t path_len = strlen(path);
    if (path_len == 1) {
        root.fs = fs;
        kprintf("Mounted \"%s\" at /\n", fs->name);
        return;
    }

    char* split_path = kstrdup(path);
    KASSERT(split_path);
    str_replace_char(split_path, PATH_SEPARATOR, '\0');

    vfs_node* node = &root;
    char* component = split_path + 1;
    for (;;) {
        KASSERT(component < split_path + path_len);
        vfs_node* child = find_child_by_name(node, component);
        if (!child)
            break;
        node = child;
        component += strlen(component) + 1;
    }

    while (component < split_path + path_len) {
        vfs_node* child = kmalloc(sizeof(vfs_node));
        KASSERT(child);
        child->name = kstrdup(component);
        KASSERT(child->name);
        append_child(node, child);
        node = child;
        component += strlen(component) + 1;
    }
    node->fs = fs;
    kprintf("Mounted \"%s\" at %s\n", fs->name, path);
}

fs_node* vfs_open(const char* pathname, int flags, mode_t mode) {
    if (!is_absolute_path(pathname))
        return ERR_PTR(-ENOTSUP);
    if ((flags & O_RDWR) != O_RDWR)
        return ERR_PTR(-ENOTSUP);
    if ((flags & O_CREAT) && ((mode & 07777) != 0777))
        return ERR_PTR(-ENOTSUP);

    size_t path_len = strlen(pathname);
    if (path_len == 1)
        return root.fs;

    char* split_pathname = kstrdup(pathname);
    if (!split_pathname)
        return ERR_PTR(-ENOMEM);
    str_replace_char(split_pathname, PATH_SEPARATOR, '\0');

    // find a file system having the longest common prefix between their mount
    // points and `pathname`
    vfs_node* vnode = &root;
    char* component = split_pathname + 1;
    while (component < split_pathname + path_len) {
        vfs_node* child = find_child_by_name(vnode, component);
        if (!child)
            break;
        vnode = child;
        component += strlen(component) + 1;
    }

    fs_node* fnode = vnode->fs;
    while (component < split_pathname + path_len) {
        fs_node* child = fs_lookup(fnode, component);
        if (IS_ERR(child)) {
            if ((PTR_ERR(child) == -ENOENT) && (flags & O_CREAT) &&
                component + strlen(component) + 1 >=
                    split_pathname + path_len) {
                fnode = fs_create_child(fnode, component, mode);
                goto created;
            }
            return child;
        }

        fnode = child;
        component += strlen(component) + 1;
    }

    if (flags & O_EXCL)
        return ERR_PTR(-EEXIST);

created:;
    int rc = fs_open(fnode, flags, mode);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    return fnode;
}
