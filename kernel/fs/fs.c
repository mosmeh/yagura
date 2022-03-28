#include "fs.h"
#include "kernel/api/errno.h"
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stat.h>
#include <kernel/kmalloc.h>
#include <kernel/kprintf.h>
#include <kernel/panic.h>
#include <stdbool.h>

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

fs_node* fs_lookup(fs_node* node, const char* name) {
    if (!node->lookup || !S_ISDIR(node->mode))
        return ERR_PTR(-ENOTDIR);
    return node->lookup(node, name);
}

fs_node* fs_create_child(fs_node* node, const char* name, mode_t mode) {
    if (!node->create_child || !S_ISDIR(node->mode))
        return ERR_PTR(-ENOTDIR);
    if (!(mode & S_IFMT))
        mode |= S_IFREG;
    return node->create_child(node, name, mode);
}

int fs_open(fs_node* node, int flags, mode_t mode) {
    if (node->open)
        return node->open(node, flags, mode);
    return 0;
}

int fs_close(file_description* desc) {
    fs_node* node = desc->node;
    if (node->close)
        return node->close(desc);
    return 0;
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
    if (!node->readdir || !S_ISDIR(node->mode))
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

fs_node* vfs_open(const char* pathname, int flags, mode_t mode) {
    if (!is_absolute_path(pathname))
        return ERR_PTR(-ENOTSUP);
    if ((flags & O_RDWR) != O_RDWR)
        return ERR_PTR(-ENOTSUP);
    if ((flags & O_CREAT) && (mode != 0777))
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
                break;
            }
            return child;
        }

        fnode = child;
        component += strlen(component) + 1;
    }

    if (flags & O_EXCL)
        return ERR_PTR(-EEXIST);

    int rc = fs_open(fnode, flags, mode);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    return fnode;
}

uint8_t mode_to_dirent_type(mode_t mode) {
    switch (mode & S_IFMT) {
    case S_IFDIR:
        return DT_DIR;
    case S_IFCHR:
        return DT_CHR;
    case S_IFBLK:
        return DT_BLK;
    case S_IFREG:
        return DT_REG;
    case S_IFIFO:
        return DT_FIFO;
    case S_IFLNK:
        return DT_LNK;
    case S_IFSOCK:
        return DT_SOCK;
    }
    KUNREACHABLE();
}
