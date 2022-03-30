#include "fs.h"
#include "kernel/mem.h"
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stat.h>
#include <kernel/boot_defs.h>
#include <kernel/kmalloc.h>
#include <kernel/panic.h>
#include <kernel/process.h>

typedef struct shm_node {
    fs_node inner;
    void* buf;
    size_t size;
    struct shm_node* first_child;
    struct shm_node* next_sibling;
} shm_node;

static shm_node* find_child_by_name(shm_node* node, const char* name) {
    shm_node* child = node->first_child;
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

static void append_child(shm_node* node, shm_node* new_child) {
    new_child->next_sibling = NULL;

    if (!node->first_child) {
        node->first_child = new_child;
        return;
    }

    shm_node* child = node->first_child;
    while (child->next_sibling)
        child = child->next_sibling;
    child->next_sibling = new_child;
}

static fs_node* shm_lookup(fs_node* node, const char* name) {
    shm_node* snode = (shm_node*)node;
    shm_node* child = find_child_by_name(snode, name);
    if (!child)
        return ERR_PTR(-ENOENT);
    return &child->inner;
}

static uintptr_t shm_mmap(file_description* desc, uintptr_t addr, size_t length,
                          int prot, off_t offset) {
    (void)offset;
    shm_node* snode = (shm_node*)desc->node;
    uintptr_t paddr = mem_to_physical_addr((uintptr_t)snode->buf);
    int rc =
        mem_map_to_physical_range(addr, paddr, length, mem_prot_to_flags(prot));
    if (IS_ERR(rc))
        return rc;
    return addr;
}

static fs_node* shm_create_child(fs_node* node, const char* name, mode_t mode) {
    shm_node* snode = (shm_node*)node;
    shm_node* child = kmalloc(sizeof(shm_node));
    if (!child)
        return ERR_PTR(-ENOMEM);
    memset(child, 0, sizeof(shm_node));
    fs_node* inner = &child->inner;
    inner->name = kstrdup(name);
    if (!inner->name)
        return ERR_PTR(-ENOMEM);
    inner->mode = mode;
    inner->mmap = shm_mmap;
    child->size = 0;
    append_child(snode, child);
    return inner;
}

static long shm_readdir(file_description* desc, void* dirp,
                        unsigned int count) {
    shm_node* snode = (shm_node*)desc->node;
    shm_node* child = snode->first_child;
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

static const char mount_point[] = "/shm/";

void shm_init(void) {
    shm_node* node = kmalloc(sizeof(shm_node));
    KASSERT(node);
    memset(node, 0, sizeof(shm_node));
    fs_node* inner = &node->inner;
    inner->name = kstrdup("shm");
    KASSERT(inner->name);
    inner->mode = S_IFDIR;
    inner->lookup = shm_lookup;
    inner->create_child = shm_create_child;
    inner->readdir = shm_readdir;
    vfs_mount(mount_point, (fs_node*)node);
}

int shm_create(const char* pathname, size_t size) {
    if (strncmp(pathname, mount_point, sizeof(mount_point) - 1) ||
        pathname[sizeof(mount_point) - 1] == '\0')
        return -EINVAL;

    fs_node* node = vfs_open(pathname, O_RDWR | O_CREAT | O_EXCL, 0777);
    if (IS_ERR(node))
        return PTR_ERR(node);

    shm_node* snode = (shm_node*)node;
    snode->buf = kaligned_alloc(PAGE_SIZE, size);
    if (!snode->buf)
        return -ENOMEM;
    snode->size = size;

    return process_alloc_file_descriptor(node);
}
