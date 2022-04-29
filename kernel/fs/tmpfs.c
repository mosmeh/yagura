#include "tree.h"
#include <common/extra.h>
#include <kernel/boot_defs.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <string.h>

typedef struct tmpfs_node {
    struct tree_node base_tree;
    uintptr_t buf_addr;
    size_t capacity, size;
    mutex lock;
} tmpfs_node;

static int tmpfs_stat(struct file* file, struct stat* buf) {
    tmpfs_node* node = (tmpfs_node*)file;
    buf->st_mode = file->mode;
    buf->st_rdev = 0;
    buf->st_size = node->size;
    return 0;
}

static ssize_t tmpfs_read(file_description* desc, void* buffer, size_t count) {
    tmpfs_node* node = (tmpfs_node*)desc->file;
    mutex_lock(&node->lock);

    if ((size_t)desc->offset >= node->size) {
        mutex_unlock(&node->lock);
        return 0;
    }
    if (desc->offset + count >= node->size)
        count = node->size - desc->offset;

    memcpy(buffer, (void*)(node->buf_addr + desc->offset), count);
    desc->offset += count;

    mutex_unlock(&node->lock);
    return count;
}

static int grow_buf(tmpfs_node* node, size_t requested_size) {
    size_t new_capacity =
        round_up(MAX(node->capacity * 2, requested_size), PAGE_SIZE);

    uintptr_t new_addr =
        range_allocator_alloc(&kernel_vaddr_allocator, new_capacity);
    if (IS_ERR(new_addr))
        return new_addr;

    if (node->buf_addr) {
        int rc = paging_copy_mapping(new_addr, node->buf_addr, node->capacity,
                                     PAGE_WRITE | PAGE_GLOBAL);
        if (IS_ERR(rc))
            return rc;
    } else {
        ASSERT(node->capacity == 0);
    }

    int rc = paging_map_to_free_pages(new_addr + node->capacity,
                                      new_capacity - node->capacity,
                                      PAGE_WRITE | PAGE_GLOBAL);
    if (IS_ERR(rc))
        return rc;

    if (node->buf_addr)
        memcpy((void*)new_addr, (void*)node->buf_addr, node->size);
    memset((void*)(new_addr + node->size), 0, new_capacity - node->size);

    paging_unmap(node->buf_addr, node->capacity);

    node->buf_addr = new_addr;
    node->capacity = new_capacity;
    return 0;
}

static ssize_t tmpfs_write(file_description* desc, const void* buffer,
                           size_t count) {
    tmpfs_node* node = (tmpfs_node*)desc->file;
    mutex_lock(&node->lock);

    if (desc->offset + count >= node->capacity) {
        int rc = grow_buf(node, desc->offset + count);
        if (IS_ERR(rc)) {
            mutex_unlock(&node->lock);
            return rc;
        }
    }

    memcpy((void*)(node->buf_addr + desc->offset), buffer, count);
    desc->offset += count;
    if (node->size < (size_t)desc->offset)
        node->size = desc->offset;

    mutex_unlock(&node->lock);
    return count;
}

static uintptr_t tmpfs_mmap(file_description* desc, uintptr_t addr,
                            size_t length, off_t offset, uint16_t page_flags) {
    if (offset != 0 || !(page_flags & PAGE_SHARED))
        return -ENOTSUP;

    tmpfs_node* node = (tmpfs_node*)desc->file;
    mutex_lock(&node->lock);

    if (length > node->size) {
        mutex_unlock(&node->lock);
        return -EINVAL;
    }

    int rc = paging_copy_mapping(addr, node->buf_addr, length, page_flags);
    if (IS_ERR(rc)) {
        mutex_unlock(&node->lock);
        return rc;
    }

    mutex_unlock(&node->lock);
    return addr;
}

static int tmpfs_truncate(file_description* desc, off_t length) {
    tmpfs_node* node = (tmpfs_node*)desc->file;
    size_t slength = (size_t)length;

    mutex_lock(&node->lock);

    if (slength <= node->size) {
        memset((void*)(node->buf_addr + slength), 0, node->size - slength);
    } else if (slength < node->capacity) {
        memset((void*)(node->buf_addr + node->size), 0, slength - node->size);
    } else {
        // slength >= capacity
        int rc = grow_buf(node, slength);
        if (IS_ERR(rc)) {
            mutex_unlock(&node->lock);
            return rc;
        }
    }

    node->size = slength;

    mutex_unlock(&node->lock);
    return 0;
}

static struct file* tmpfs_create_child(struct file* file, const char* name,
                                       mode_t mode) {
    tmpfs_node* node = (tmpfs_node*)file;
    tmpfs_node* child = kmalloc(sizeof(tmpfs_node));
    if (!child)
        return ERR_PTR(-ENOMEM);
    *child = (tmpfs_node){0};

    mutex_init(&child->lock);

    struct file* child_file = (struct file*)child;
    child_file->name = kstrdup(name);
    if (!child_file->name)
        return ERR_PTR(-ENOMEM);
    child_file->mode = mode;
    child_file->stat = tmpfs_stat;
    if (S_ISDIR(mode)) {
        child_file->lookup = tree_node_lookup;
        child_file->create_child = tmpfs_create_child;
        child_file->readdir = tree_node_readdir;
    } else {
        child_file->read = tmpfs_read;
        child_file->write = tmpfs_write;
        child_file->mmap = tmpfs_mmap;
        child_file->truncate = tmpfs_truncate;
    }

    mutex_lock(&node->lock);
    tree_node_append_child((tree_node*)node, (tree_node*)child);
    mutex_unlock(&node->lock);
    return child_file;
}

struct file* tmpfs_create_root(void) {
    tmpfs_node* root = kmalloc(sizeof(tmpfs_node));
    if (!root)
        return ERR_PTR(-ENOMEM);
    *root = (tmpfs_node){0};

    mutex_init(&root->lock);

    struct file* file = (struct file*)root;
    file->name = kstrdup("tmpfs");
    if (!file->name)
        return ERR_PTR(-ENOMEM);
    file->mode = S_IFDIR;
    file->stat = tmpfs_stat;
    file->lookup = tree_node_lookup;
    file->create_child = tmpfs_create_child;
    file->readdir = tree_node_readdir;

    return file;
}
