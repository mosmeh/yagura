#include "tree.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/stat.h>
#include <kernel/kmalloc.h>

typedef struct tmpfs_node {
    struct tree_node base_tree;
    void* buf;
    size_t capacity, size;
} tmpfs_node;

static ssize_t tmpfs_read(file_description* desc, void* buffer, size_t count) {
    tmpfs_node* node = (tmpfs_node*)desc->file;
    if ((size_t)desc->offset >= node->size)
        return 0;
    if (desc->offset + count >= node->size)
        count = node->size - desc->offset;

    memcpy(buffer, (void*)((uintptr_t)node->buf + desc->offset), count);
    desc->offset += count;
    return count;
}

static int grow_buf(tmpfs_node* node, size_t requested_size) {
    size_t new_capacity = MAX(node->capacity * 2, requested_size);
    void* buf = kmalloc(new_capacity);
    if (!buf)
        return -ENOMEM;
    memcpy(buf, node->buf, node->size);
    memset((void*)((uintptr_t)buf + node->size), 0, new_capacity - node->size);
    node->buf = buf;
    node->capacity = new_capacity;
    return 0;
}

static ssize_t tmpfs_write(file_description* desc, const void* buffer,
                           size_t count) {
    tmpfs_node* node = (tmpfs_node*)desc->file;
    if (desc->offset + count >= node->capacity) {
        int rc = grow_buf(node, desc->offset + count);
        if (IS_ERR(rc))
            return rc;
    }

    memcpy((void*)((uintptr_t)node->buf + desc->offset), buffer, count);
    desc->offset += count;
    if (node->size < (size_t)desc->offset)
        node->size = desc->offset;
    return count;
}

static int tmpfs_truncate(file_description* desc, off_t length) {
    tmpfs_node* node = (tmpfs_node*)desc->file;
    size_t slength = (size_t)length;

    if (slength <= node->size) {
        memset((void*)((uintptr_t)node->buf + slength), 0,
               node->size - slength);
    } else if (slength < node->capacity) {
        memset((void*)((uintptr_t)node->buf + node->size), 0,
               slength - node->size);
    } else {
        // slength >= capacity
        int rc = grow_buf(node, slength);
        if (IS_ERR(rc))
            return rc;
    }

    node->size = slength;
    return 0;
}

static struct file* tmpfs_create_child(struct file* file, const char* name,
                                       mode_t mode) {
    tmpfs_node* node = (tmpfs_node*)file;
    tmpfs_node* child = kmalloc(sizeof(tmpfs_node));
    if (!child)
        return ERR_PTR(-ENOMEM);
    memset(child, 0, sizeof(tmpfs_node));
    struct file* child_file = (struct file*)child;
    child_file->name = kstrdup(name);
    if (!child_file->name)
        return ERR_PTR(-ENOMEM);
    child_file->mode = mode;
    child_file->read = tmpfs_read;
    child_file->write = tmpfs_write;
    child_file->truncate = tmpfs_truncate;
    child->capacity = child->size = 0;
    tree_node_append_child((tree_node*)node, (tree_node*)child);
    return child_file;
}

struct file* tmpfs_create_root(void) {
    tmpfs_node* root = kmalloc(sizeof(tmpfs_node));
    if (!root)
        return ERR_PTR(-ENOMEM);
    memset(root, 0, sizeof(tmpfs_node));
    struct file* file = (struct file*)root;
    file->name = kstrdup("tmpfs");
    if (!file->name)
        return ERR_PTR(-ENOMEM);
    file->mode = S_IFDIR;
    file->lookup = tree_node_lookup;
    file->create_child = tmpfs_create_child;
    file->readdir = tree_node_readdir;

    return file;
}
