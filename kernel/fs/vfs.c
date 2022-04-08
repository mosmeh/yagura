#include "fs.h"
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/kmalloc.h>
#include <kernel/kprintf.h>
#include <kernel/panic.h>
#include <stdbool.h>
#include <string.h>

typedef struct vfs_node {
    char* name;
    struct file* fs;
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

void vfs_mount(const char* path, struct file* fs) {
    ASSERT(is_absolute_path(path));

    size_t path_len = strlen(path);
    if (path_len == 1) {
        root.fs = fs;
        kprintf("Mounted \"%s\" at /\n", fs->name);
        return;
    }

    char* split_path = kstrdup(path);
    ASSERT(split_path);
    str_replace_char(split_path, PATH_SEPARATOR, '\0');

    vfs_node* node = &root;
    char* component = split_path + 1;
    for (;;) {
        ASSERT(component < split_path + path_len);
        vfs_node* child = find_child_by_name(node, component);
        if (!child)
            break;
        node = child;
        component += strlen(component) + 1;
    }

    while (component < split_path + path_len) {
        vfs_node* child = kmalloc(sizeof(vfs_node));
        ASSERT(child);
        child->name = kstrdup(component);
        ASSERT(child->name);
        append_child(node, child);
        node = child;
        component += strlen(component) + 1;
    }
    node->fs = fs;
    kprintf("Mounted \"%s\" at %s\n", fs->name, path);
}

static struct file* get_or_create_file(const char* pathname, int flags,
                                       mode_t mode) {
    if (!is_absolute_path(pathname))
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
    ASSERT(vnode);
    ASSERT(vnode->fs);

    struct file* file = vnode->fs;
    while (component < split_pathname + path_len) {
        struct file* child = fs_lookup(file, component);
        if (IS_ERR(child)) {
            if ((PTR_ERR(child) == -ENOENT) && (flags & O_CREAT) &&
                component + strlen(component) + 1 >=
                    split_pathname + path_len) {
                file = fs_create_child(file, component, mode);
                goto found_or_created;
            }
            return child;
        }

        file = child;
        component += strlen(component) + 1;
    }

    if (flags & O_EXCL)
        return ERR_PTR(-EEXIST);

found_or_created:
    ASSERT(file);
    int rc = fs_open(file, flags, mode);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    return file;
}

file_description* vfs_open(const char* pathname, int flags, mode_t mode) {
    struct file* file = get_or_create_file(pathname, flags, mode);
    if (IS_ERR(file))
        return ERR_CAST(file);

    file_description* desc = kmalloc(sizeof(file_description));
    if (!desc)
        return ERR_PTR(-ENOMEM);
    desc->file = file;
    desc->offset = 0;
    desc->flags = flags;
    return desc;
}
