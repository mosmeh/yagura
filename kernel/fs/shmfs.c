#include "kernel/mem.h"
#include "tree.h"
#include <common/extra.h>
#include <kernel/api/stat.h>
#include <kernel/boot_defs.h>
#include <kernel/kmalloc.h>
#include <kernel/panic.h>
#include <string.h>

typedef struct shmfs_node {
    tree_node base_tree;
    void* buf;
    size_t capacity, size;
} shmfs_node;

static uintptr_t shmfs_mmap(file_description* desc, uintptr_t addr,
                            size_t length, int prot, off_t offset) {
    (void)offset;
    shmfs_node* node = (shmfs_node*)desc->file;
    if (length > node->size)
        return -EINVAL;
    uintptr_t paddr = mem_to_physical_addr((uintptr_t)node->buf);
    int rc =
        mem_map_to_physical_range(addr, paddr, length, mem_prot_to_flags(prot));
    if (IS_ERR(rc))
        return rc;
    return addr;
}

static int shmfs_truncate(file_description* desc, off_t length) {
    shmfs_node* node = (shmfs_node*)desc->file;
    if (node->buf) {
        size_t slength = (size_t)length;
        if (slength > node->capacity)
            return -ENOTSUP;
        if (slength < node->size) {
            memset((void*)((uintptr_t)node->buf + slength), 0,
                   node->size - slength);
        }
        node->size = slength;
    } else {
        node->capacity = node->size = round_up(length, PAGE_SIZE);
        node->buf = kaligned_alloc(PAGE_SIZE, node->size);
        if (!node->buf)
            return -ENOMEM;
        memset(node->buf, 0, node->size);
    }
    return 0;
}

static struct file* shmfs_create_child(struct file* file, const char* name,
                                       mode_t mode) {
    shmfs_node* node = (shmfs_node*)file;
    shmfs_node* child = kmalloc(sizeof(shmfs_node));
    if (!child)
        return ERR_PTR(-ENOMEM);
    memset(child, 0, sizeof(shmfs_node));
    struct file* child_file = (struct file*)child;
    child_file->name = kstrdup(name);
    if (!child_file->name)
        return ERR_PTR(-ENOMEM);
    child_file->mode = mode;
    child_file->mmap = shmfs_mmap;
    child_file->truncate = shmfs_truncate;
    tree_node_append_child((tree_node*)node, (tree_node*)child);
    return child_file;
}

struct file* shmfs_create_root(void) {
    shmfs_node* node = kmalloc(sizeof(shmfs_node));
    if (!node)
        return ERR_PTR(-ENOMEM);
    memset(node, 0, sizeof(shmfs_node));
    struct file* file = (struct file*)node;
    file->name = kstrdup("shmfs");
    if (!file->name)
        return ERR_PTR(-ENOMEM);
    file->mode = S_IFDIR;
    file->lookup = tree_node_lookup;
    file->create_child = shmfs_create_child;
    file->readdir = tree_node_readdir;
    return file;
}
