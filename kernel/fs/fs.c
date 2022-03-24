#include "fs.h"
#include <common/string.h>
#include <kernel/kmalloc.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>
#include <kernel/system.h>
#include <stdbool.h>

uint32_t fs_read(fs_node* node, off_t offset, size_t size, void* buffer) {
    if (!node->read)
        return 0;

    return node->read(node, offset, size, buffer);
}

uint32_t fs_write(fs_node* node, off_t offset, size_t size,
                  const void* buffer) {
    if (!node->write)
        return 0;

    return node->write(node, offset, size, buffer);
}

void fs_open(fs_node* node, int flags) {
    if (node->open)
        node->open(node, flags);
}

void fs_close(fs_node* node) {
    if (node->close)
        node->close(node);
}

dirent* fs_readdir(fs_node* node, size_t index) {
    if (!node->readdir)
        return NULL;

    return node->readdir(node, index);
}

fs_node* fs_finddir(fs_node* node, const char* name) {
    if (!node->finddir)
        return NULL;

    return node->finddir(node, name);
}

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

    while (true) {
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

void vfs_mount(char* path, fs_node* fs) {
    KASSERT(path[0] == PATH_SEPARATOR);

    size_t path_len = strlen(path);
    if (path_len == 1) {
        root.fs = fs;
        kprintf("Mounted \"%s\" at /\n", fs->name);
        return;
    }

    char* split_path = kstrdup(path);
    str_replace_char(split_path, PATH_SEPARATOR, '\0');

    vfs_node* node = &root;
    char* component = split_path + 1;
    while (true) {
        KASSERT(component < split_path + path_len);
        vfs_node* child = find_child_by_name(node, component);
        if (!child)
            break;
        node = child;
        component += strlen(component) + 1;
    }

    while (component < split_path + path_len) {
        vfs_node* child = kmalloc(sizeof(vfs_node));
        child->name = kstrdup(component);
        append_child(node, child);
        node = child;
        component += strlen(component) + 1;
    }
    node->fs = fs;
    kprintf("Mounted \"%s\" at %s\n", fs->name, path);
}

fs_node* vfs_find_by_pathname(const char* pathname) {
    if (pathname[0] != PATH_SEPARATOR) {
        KUNIMPLEMENTED();
    }
    char* canonicalized_pathname = (char*)pathname;

    size_t path_len = strlen(canonicalized_pathname);
    if (path_len == 1) {
        return root.fs;
    }

    char* split_pathname = canonicalized_pathname;
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
        fs_node* child = fs_finddir(fnode, component);
        KASSERT(child);

        fnode = child;
        component += strlen(component) + 1;
    }
    return fnode;
}
