#include "fs.h"
#include "kernel/panic.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/err.h>
#include <kernel/api/stat.h>
#include <kernel/kmalloc.h>

typedef struct tmpfs_node {
    fs_node inner;
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

static ssize_t tmpfs_read(file_description* desc, void* buffer, size_t count) {
    tmpfs_node* tnode = (tmpfs_node*)desc->node;
    if ((size_t)desc->offset >= tnode->size)
        return 0;
    if (desc->offset + count >= tnode->size)
        count = tnode->size - desc->offset;

    memcpy(buffer, (void*)((uintptr_t)tnode->buf + desc->offset), count);
    desc->offset += count;
    return count;
}

static int grow_buf(tmpfs_node* tnode, size_t requested_size) {
    size_t new_capacity = MAX(tnode->capacity * 2, requested_size);
    void* buf = kmalloc(new_capacity);
    if (!buf)
        return -ENOMEM;
    memcpy(buf, tnode->buf, tnode->size);
    memset((void*)((uintptr_t)buf + tnode->size), 0,
           new_capacity - tnode->size);
    tnode->buf = buf;
    tnode->capacity = new_capacity;
    return 0;
}

static ssize_t tmpfs_write(file_description* desc, const void* buffer,
                           size_t count) {
    tmpfs_node* tnode = (tmpfs_node*)desc->node;
    if (desc->offset + count >= tnode->capacity) {
        int rc = grow_buf(tnode, desc->offset + count);
        if (IS_ERR(rc))
            return rc;
    }

    memcpy((void*)((uintptr_t)tnode->buf + desc->offset), buffer, count);
    desc->offset += count;
    if (tnode->size < (size_t)desc->offset)
        tnode->size = desc->offset;
    return count;
}

static int tmpfs_truncate(file_description* desc, off_t length) {
    tmpfs_node* tnode = (tmpfs_node*)desc->node;
    size_t slength = (size_t)length;

    if (slength <= tnode->size) {
        memset((void*)((uintptr_t)tnode->buf + slength), 0,
               tnode->size - slength);
    } else if (slength < tnode->capacity) {
        memset((void*)((uintptr_t)tnode->buf + tnode->size), 0,
               slength - tnode->size);
    } else {
        // slength >= capacity
        int rc = grow_buf(tnode, slength);
        if (IS_ERR(rc))
            return rc;
    }

    tnode->size = slength;
    return 0;
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
    inner->truncate = tmpfs_truncate;
    child->capacity = child->size = 0;
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
