#include "fs.h"
#include <common/errno.h>
#include <common/string.h>
#include <kernel/kmalloc.h>
#include <kernel/kprintf.h>
#include <kernel/system.h>
#include <stdbool.h>

fs_node* fs_lookup(fs_node* node, const char* name) {
    if (!node->lookup)
        return NULL;
    KASSERT(node->type == FS_DIRECTORY);
    return node->lookup(node, name);
}

void fs_open(fs_node* node, int flags) {
    if (node->open)
        node->open(node, flags);
}

void fs_close(file_description* desc) {
    fs_node* node = desc->node;
    if (node->close)
        node->close(desc);
}

ssize_t fs_read(file_description* desc, void* buffer, size_t size) {
    fs_node* node = desc->node;
    if (!node->read)
        return 0;
    return node->read(desc, buffer, size);
}

ssize_t fs_write(file_description* desc, const void* buffer, size_t size) {
    fs_node* node = desc->node;
    if (!node->write)
        return 0;
    return node->write(desc, buffer, size);
}

uintptr_t fs_mmap(file_description* desc, uintptr_t vaddr, size_t length,
                  int prot, off_t offset) {
    fs_node* node = desc->node;
    if (!node->mmap)
        return -ENODEV;
    return node->mmap(desc, vaddr, length, prot, offset);
}

int fs_ioctl(file_description* desc, int request, void* argp) {
    fs_node* node = desc->node;
    if (!node->ioctl)
        return -ENOTTY;
    node->ioctl(desc, request, argp);
    return 0;
}

long fs_readdir(file_description* desc, void* dirp, unsigned int count) {
    fs_node* node = desc->node;
    if (!node->readdir || node->type != FS_DIRECTORY)
        return -ENOTDIR;
    return node->readdir(desc, dirp, count);
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

void vfs_mount(char* path, fs_node* fs) {
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

fs_node* vfs_find_node_by_pathname(const char* pathname) {
    if (!is_absolute_path(pathname))
        KUNIMPLEMENTED();

    size_t path_len = strlen(pathname);
    if (path_len == 1) {
        return root.fs;
    }

    char* split_pathname = kstrdup(pathname);
    KASSERT(split_pathname);
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
        if (!child)
            return NULL;

        fnode = child;
        component += strlen(component) + 1;
    }
    return fnode;
}

int file_descriptor_table_init(file_descriptor_table* table) {
    table->entries = kmalloc(FD_TABLE_CAPACITY * sizeof(file_description));
    if (!table->entries)
        return -ENOMEM;

    memset(table->entries, 0, FD_TABLE_CAPACITY * sizeof(file_description));
    return 0;
}

int file_descriptor_table_clone_from(file_descriptor_table* to,
                                     const file_descriptor_table* from) {
    to->entries = kmalloc(FD_TABLE_CAPACITY * sizeof(file_description));
    if (!to->entries)
        return -ENOMEM;

    memcpy(to->entries, from->entries,
           FD_TABLE_CAPACITY * sizeof(file_description));
    return 0;
}
