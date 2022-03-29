#include "fs.h"
#include "kernel/panic.h"
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/err.h>
#include <kernel/api/stat.h>
#include <kernel/kmalloc.h>

#define BUF_CAPACITY 1024

typedef struct tmpfs_node {
    fs_node inner;
    void* buf;
    size_t buf_size;
    struct tmpfs_node* first_child;
    struct tmpfs_node* next_sibling;
} tmpfs_node;

static tmpfs_node* find_child_by_name(tmpfs_node* node, const char* name) {
    tmpfs_node* child = node->first_child;
    if (!child)
        return NULL;

    for (;;) {
        if (!strcmp(child->inner.name, name))
            return child;

        if (!child->next_sibling)
            return NULL;

        child = child->next_sibling;
    }
}

static void append_child(tmpfs_node* node, tmpfs_node* new_child) {
    new_child->next_sibling = NULL;

    if (!node->first_child) {
        node->first_child = new_child;
        return;
    }

    tmpfs_node* child = node->first_child;
    while (child->next_sibling)
        child = child->next_sibling;
    child->next_sibling = new_child;
}

static fs_node* tmpfs_lookup(fs_node* node, const char* name) {
    tmpfs_node* tnode = (tmpfs_node*)node;
    tmpfs_node* child = find_child_by_name(tnode, name);
    if (!child)
        return ERR_PTR(-ENOENT);
    return &child->inner;
}

static ssize_t tmpfs_read(file_description* desc, void* buffer, size_t size) {
    tmpfs_node* tnode = (tmpfs_node*)desc->node;
    if ((size_t)desc->offset >= tnode->buf_size)
        return 0;
    if (desc->offset + size >= tnode->buf_size)
        size = tnode->buf_size - desc->offset;

    memcpy(buffer, (void*)((uintptr_t)tnode->buf + desc->offset), size);
    desc->offset += size;
    return size;
}

static ssize_t tmpfs_write(file_description* desc, const void* buffer,
                           size_t size) {
    tmpfs_node* tnode = (tmpfs_node*)desc->node;
    if (desc->offset >= BUF_CAPACITY)
        return -ENOSPC;
    if (desc->offset + size >= BUF_CAPACITY)
        size = BUF_CAPACITY - desc->offset;

    memcpy((void*)((uintptr_t)tnode->buf + desc->offset), buffer, size);
    desc->offset += size;
    return size;
}

static fs_node* tmpfs_create_child(fs_node* node, const char* name,
                                   mode_t mode) {
    tmpfs_node* tnode = (tmpfs_node*)node;
    tmpfs_node* child = kmalloc(sizeof(tmpfs_node));
    if (!child)
        return ERR_PTR(-ENOMEM);
    memset(child, 0, sizeof(tmpfs_node));
    fs_node* inner = &child->inner;
    inner->name = kstrdup(name);
    if (!inner->name)
        return ERR_PTR(-ENOMEM);
    inner->mode = mode;
    inner->read = tmpfs_read;
    inner->write = tmpfs_write;
    child->buf = kmalloc(BUF_CAPACITY);
    if (!child->buf)
        return ERR_PTR(-ENOMEM);
    append_child(tnode, child);
    return inner;
}

static long tmpfs_readdir(file_description* desc, void* dirp,
                          unsigned int count) {
    tmpfs_node* tnode = (tmpfs_node*)desc->node;
    tmpfs_node* child = tnode->first_child;
    if (!child)
        return 0;

    for (off_t i = 0; i < desc->offset; ++i) {
        child = child->next_sibling;
        if (!child)
            return 0;
    }

    uintptr_t buf = (uintptr_t)dirp;
    long nread = 0;

    while (count > 0 && child) {
        fs_node* node = &child->inner;
        size_t name_len = strlen(node->name);
        size_t size = offsetof(dirent, name) + name_len + 1;
        if (count < size)
            break;

        dirent* dent = (dirent*)buf;
        dent->type = mode_to_dirent_type(node->mode);
        dent->record_len = size;
        strcpy(dent->name, node->name);
        dent->name[name_len] = '\0';

        ++desc->offset;
        child = child->next_sibling;
        nread += size;
        buf += size;
        count -= size;
    }

    if (nread == 0)
        return -EINVAL;
    return nread;
}

fs_node* tmpfs_create(void) {
    tmpfs_node* root = kmalloc(sizeof(tmpfs_node));
    if (!root)
        return ERR_PTR(-ENOMEM);
    memset(root, 0, sizeof(tmpfs_node));
    fs_node* inner = &root->inner;
    inner->name = kstrdup("tmpfs");
    if (!inner->name)
        return ERR_PTR(-ENOMEM);
    inner->mode = S_IFDIR;
    inner->lookup = tmpfs_lookup;
    inner->create_child = tmpfs_create_child;
    inner->readdir = tmpfs_readdir;

    return inner;
}
