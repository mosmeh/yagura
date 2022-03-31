#include "kernel/mem.h"
#include "tree.h"
#include <common/panic.h>
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stat.h>
#include <kernel/boot_defs.h>
#include <kernel/kmalloc.h>
#include <kernel/process.h>

typedef struct shm_node {
    tree_node base_tree;
    void* buf;
    size_t size;
} shm_node;

static uintptr_t shm_mmap(file_description* desc, uintptr_t addr, size_t length,
                          int prot, off_t offset) {
    (void)offset;
    shm_node* node = (shm_node*)desc->file;
    uintptr_t paddr = mem_to_physical_addr((uintptr_t)node->buf);
    int rc =
        mem_map_to_physical_range(addr, paddr, length, mem_prot_to_flags(prot));
    if (IS_ERR(rc))
        return rc;
    return addr;
}

static struct file* shm_create_child(struct file* file, const char* name,
                                     mode_t mode) {
    shm_node* node = (shm_node*)file;
    shm_node* child = kmalloc(sizeof(shm_node));
    if (!child)
        return ERR_PTR(-ENOMEM);
    memset(child, 0, sizeof(shm_node));
    struct file* child_file = (struct file*)child;
    child_file->name = kstrdup(name);
    if (!child_file->name)
        return ERR_PTR(-ENOMEM);
    child_file->mode = mode;
    child_file->mmap = shm_mmap;
    child->size = 0;
    tree_node_append_child((tree_node*)node, (tree_node*)child);
    return child_file;
}

static const char mount_point[] = "/shm/";

void shm_init(void) {
    shm_node* node = kmalloc(sizeof(shm_node));
    ASSERT(node);
    memset(node, 0, sizeof(shm_node));
    struct file* file = (struct file*)node;
    file->name = kstrdup("shm");
    ASSERT(file->name);
    file->mode = S_IFDIR;
    file->lookup = tree_node_lookup;
    file->create_child = shm_create_child;
    file->readdir = tree_node_readdir;
    vfs_mount(mount_point, (struct file*)node);
}

int shm_create(const char* pathname, size_t size) {
    if (strncmp(pathname, mount_point, sizeof(mount_point) - 1) ||
        pathname[sizeof(mount_point) - 1] == '\0')
        return -EINVAL;

    struct file* file = vfs_open(pathname, O_RDWR | O_CREAT | O_EXCL, 0777);
    if (IS_ERR(file))
        return PTR_ERR(file);

    shm_node* node = (shm_node*)file;
    node->buf = kaligned_alloc(PAGE_SIZE, size);
    if (!node->buf)
        return -ENOMEM;
    node->size = size;

    return process_alloc_file_descriptor(file);
}
