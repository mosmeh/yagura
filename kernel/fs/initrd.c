#include "fs.h"
#include <common/initrd.h>
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/err.h>
#include <kernel/kmalloc.h>
#include <kernel/panic.h>

static uintptr_t initrd_addr;
static const initrd_header* header;
static const initrd_file_header* file_headers;
static fs_node* file_nodes;

static ssize_t initrd_read(file_description* desc, void* buffer, size_t size) {
    const initrd_file_header* header = file_headers + desc->node->ino;
    if (desc->offset > header->length)
        return 0;
    if (desc->offset + size > header->length)
        size = header->length - desc->offset;

    memcpy(buffer,
           (void*)(uintptr_t)(initrd_addr + header->offset + desc->offset),
           size);
    desc->offset += size;

    return size;
}

static fs_node* initrd_lookup(fs_node* node, const char* name) {
    (void)node;
    for (size_t i = 0; i < header->num_files; ++i)
        if (!strcmp(name, file_nodes[i].name))
            return file_nodes + i;
    return ERR_PTR(-ENOENT);
}

long initrd_readdir(file_description* desc, void* dirp, unsigned int count) {
    uintptr_t buf = (uintptr_t)dirp;
    long nread = 0;

    while (count > 0 && (size_t)desc->offset < header->num_files) {
        fs_node* node = file_nodes + desc->offset;
        size_t size = offsetof(dirent, name) + strlen(node->name) + 1;
        if (count < size)
            break;

        dirent* dent = (dirent*)buf;
        dent->type = node->type;
        dent->ino = node->ino;
        dent->record_len = size;
        strcpy(dent->name, node->name);

        ++desc->offset;
        nread += size;
        buf += size;
        count -= size;
    }

    if (nread == 0)
        return -EINVAL;
    return nread;
}

void initrd_init(uintptr_t addr) {
    initrd_addr = addr;
    header = (const initrd_header*)addr;
    file_headers = (const initrd_file_header*)(addr + sizeof(initrd_header));

    file_nodes = kmalloc(header->num_files * sizeof(fs_node));
    KASSERT(file_nodes);
    for (size_t i = 0; i < header->num_files; ++i) {
        fs_node* node = file_nodes + i;
        memset(node, 0, sizeof(fs_node));
        node->name = kstrndup(file_headers[i].name, 128);
        KASSERT(node->name);
        node->type = DT_REG;
        node->read = initrd_read;
        node->ino = i;
    }
}

fs_node* initrd_create(void) {
    fs_node* root = kmalloc(sizeof(fs_node));
    if (!root)
        return ERR_PTR(-ENOMEM);

    memset(root, 0, sizeof(fs_node));

    root->name = kstrdup("initrd");
    if (!root->name)
        return ERR_PTR(-ENOMEM);

    root->type = DT_DIR;
    root->lookup = initrd_lookup;
    root->readdir = initrd_readdir;

    return root;
}
