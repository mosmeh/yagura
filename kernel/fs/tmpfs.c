#include "dentry.h"
#include <kernel/boot_defs.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <string.h>

typedef struct tmpfs_inode {
    struct inode inode;
    uintptr_t buf_addr;
    size_t capacity, size;
    mutex lock;
    struct dentry* children;
} tmpfs_inode;

static struct inode* tmpfs_lookup_child(struct inode* inode, const char* name) {
    tmpfs_inode* node = (tmpfs_inode*)inode;
    mutex_lock(&node->lock);
    struct inode* child = dentry_find(node->children, name);
    mutex_unlock(&node->lock);
    return child;
}

static int tmpfs_stat(struct inode* inode, struct stat* buf) {
    tmpfs_inode* node = (tmpfs_inode*)inode;
    buf->st_mode = inode->mode;
    buf->st_rdev = 0;
    buf->st_size = node->size;
    return 0;
}

static ssize_t tmpfs_read(file_description* desc, void* buffer, size_t count) {
    tmpfs_inode* node = (tmpfs_inode*)desc->inode;
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

static int grow_buf(tmpfs_inode* node, size_t requested_size) {
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
    tmpfs_inode* node = (tmpfs_inode*)desc->inode;
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

    tmpfs_inode* node = (tmpfs_inode*)desc->inode;
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
    tmpfs_inode* node = (tmpfs_inode*)desc->inode;
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

static long tmpfs_readdir(file_description* desc, void* dirp,
                          unsigned int count) {
    tmpfs_inode* node = (tmpfs_inode*)desc->inode;
    mutex_lock(&node->lock);
    long rc = dentry_readdir(node->children, dirp, count, &desc->offset);
    mutex_unlock(&node->lock);
    return rc;
}

static int tmpfs_link_child(struct inode* inode, const char* name,
                            struct inode* child) {
    tmpfs_inode* node = (tmpfs_inode*)inode;
    mutex_lock(&node->lock);
    int rc = dentry_append(&node->children, name, child);
    mutex_unlock(&node->lock);
    return rc;
}

static struct inode* tmpfs_unlink_child(struct inode* inode, const char* name) {
    tmpfs_inode* node = (tmpfs_inode*)inode;
    return dentry_remove(&node->children, name);
}

static struct inode* tmpfs_create_child(struct inode* inode, const char* name,
                                        mode_t mode);

static file_ops dir_fops = {.lookup_child = tmpfs_lookup_child,
                            .create_child = tmpfs_create_child,
                            .link_child = tmpfs_link_child,
                            .unlink_child = tmpfs_unlink_child,
                            .stat = tmpfs_stat,
                            .readdir = tmpfs_readdir};
static file_ops non_dir_fops = {.stat = tmpfs_stat,
                                .read = tmpfs_read,
                                .write = tmpfs_write,
                                .mmap = tmpfs_mmap,
                                .truncate = tmpfs_truncate};

static struct inode* tmpfs_create_child(struct inode* inode, const char* name,
                                        mode_t mode) {
    tmpfs_inode* child = kmalloc(sizeof(tmpfs_inode));
    if (!child)
        return ERR_PTR(-ENOMEM);
    *child = (tmpfs_inode){0};

    mutex_init(&child->lock);

    struct inode* child_inode = &child->inode;
    child_inode->fops = S_ISDIR(mode) ? &dir_fops : &non_dir_fops;
    child_inode->mode = mode;

    int rc = tmpfs_link_child(inode, name, child_inode);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    return child_inode;
}

struct inode* tmpfs_create_root(void) {
    tmpfs_inode* root = kmalloc(sizeof(tmpfs_inode));
    if (!root)
        return ERR_PTR(-ENOMEM);
    *root = (tmpfs_inode){0};

    mutex_init(&root->lock);

    struct inode* inode = &root->inode;
    inode->fops = &dir_fops;
    inode->mode = S_IFDIR;

    return inode;
}
