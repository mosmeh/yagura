#include "fs.h"
#include "kernel/panic.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/err.h>
#include <kernel/api/stat.h>
#include <kernel/kmalloc.h>

typedef struct tmpfs_node {
    struct file base_file;
    void* buf;
    size_t capacity, size;
    struct tmpfs_node* first_child;
    struct tmpfs_node* next_sibling;
} tmpfs_node;

static tmpfs_node* find_child_by_name(tmpfs_node* node, const char* name) {
    tmpfs_node* child = node->first_child;
    if (!child)
        return NULL;

    for (;;) {
        if (!strcmp(child->base_file.name, name))
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

static struct file* tmpfs_lookup(struct file* file, const char* name) {
    tmpfs_node* node = (tmpfs_node*)file;
    tmpfs_node* child = find_child_by_name(node, name);
    if (!child)
        return ERR_PTR(-ENOENT);
    return &child->base_file;
}

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
    struct file* child_file = &child->base_file;
    child_file->name = kstrdup(name);
    if (!child_file->name)
        return ERR_PTR(-ENOMEM);
    child_file->mode = mode;
    child_file->read = tmpfs_read;
    child_file->write = tmpfs_write;
    child_file->truncate = tmpfs_truncate;
    child->capacity = child->size = 0;
    append_child(node, child);
    return child_file;
}

static long tmpfs_readdir(file_description* desc, void* dirp,
                          unsigned int count) {
    tmpfs_node* node = (tmpfs_node*)desc->file;
    tmpfs_node* child = node->first_child;
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
        struct file* file = &child->base_file;
        size_t name_len = strlen(file->name);
        size_t size = offsetof(dirent, name) + name_len + 1;
        if (count < size)
            break;

        dirent* dent = (dirent*)buf;
        dent->type = mode_to_dirent_type(file->mode);
        dent->record_len = size;
        strcpy(dent->name, file->name);
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

struct file* tmpfs_create(void) {
    tmpfs_node* root = kmalloc(sizeof(tmpfs_node));
    if (!root)
        return ERR_PTR(-ENOMEM);
    memset(root, 0, sizeof(tmpfs_node));
    struct file* file = &root->base_file;
    file->name = kstrdup("tmpfs");
    if (!file->name)
        return ERR_PTR(-ENOMEM);
    file->mode = S_IFDIR;
    file->lookup = tmpfs_lookup;
    file->create_child = tmpfs_create_child;
    file->readdir = tmpfs_readdir;

    return file;
}
