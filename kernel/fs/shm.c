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
    struct file base_file;
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
        if (!strcmp(child->base_file.name, name))
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

static struct file* shm_lookup(struct file* file, const char* name) {
    shm_node* node = (shm_node*)file;
    shm_node* child = find_child_by_name(node, name);
    if (!child)
        return ERR_PTR(-ENOENT);
    return &child->base_file;
}

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
    struct file* child_file = &child->base_file;
    child_file->name = kstrdup(name);
    if (!child_file->name)
        return ERR_PTR(-ENOMEM);
    child_file->mode = mode;
    child_file->mmap = shm_mmap;
    child->size = 0;
    append_child(node, child);
    return child_file;
}

static long shm_readdir(file_description* desc, void* dirp,
                        unsigned int count) {
    shm_node* node = (shm_node*)desc->file;
    shm_node* child = node->first_child;
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

static const char mount_point[] = "/shm/";

void shm_init(void) {
    shm_node* node = kmalloc(sizeof(shm_node));
    KASSERT(node);
    memset(node, 0, sizeof(shm_node));
    struct file* file = &node->base_file;
    file->name = kstrdup("shm");
    KASSERT(file->name);
    file->mode = S_IFDIR;
    file->lookup = shm_lookup;
    file->create_child = shm_create_child;
    file->readdir = shm_readdir;
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
