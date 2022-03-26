#include "fs.h"
#include <common/initrd.h>
#include <common/string.h>
#include <kernel/kmalloc.h>

static size_t num_files;
static const initrd_file_header* file_headers;
static fs_node* file_nodes;
static uintptr_t file_start;

static ssize_t initrd_read(fs_node* node, off_t offset, size_t size,
                           void* buffer) {
    const initrd_file_header* header = file_headers + node->inode;
    if (offset > header->length)
        return 0;
    if (offset + size > header->length)
        size = header->length - offset;
    memcpy(buffer, (void*)(uintptr_t)(file_start + header->offset + offset),
           size);
    return size;
}

static dirent* initrd_readdir(fs_node* node, size_t index) {
    (void)node;
    static dirent dent;
    if (index >= num_files)
        return NULL;
    fs_node* n = file_nodes + index;
    dent.name = kstrdup(n->name);
    dent.ino = n->inode;
    return &dent;
}

static fs_node* initrd_finddir(fs_node* node, const char* name) {
    (void)node;
    for (size_t i = 0; i < num_files; ++i)
        if (!strcmp(name, file_nodes[i].name))
            return file_nodes + i;
    return NULL;
}

void initrd_init(uintptr_t paddr) {
    const initrd_header* header = (const initrd_header*)paddr;
    num_files = header->num_files;
    file_headers = (const initrd_file_header*)(paddr + sizeof(initrd_header));
    file_start =
        paddr + sizeof(initrd_header) + num_files * sizeof(initrd_file_header);

    file_nodes = kmalloc(num_files * sizeof(fs_node));
    for (size_t i = 0; i < num_files; ++i) {
        fs_node* node = file_nodes + i;
        memset(node, 0, sizeof(fs_node));
        node->name = kstrndup(file_headers[i].name, 128);
        node->flags = FS_FILE;
        node->length = file_headers[i].length;
        node->inode = i;
        node->read = initrd_read;
    }
}

fs_node* initrd_create(void) {
    fs_node* root = kmalloc(sizeof(fs_node));
    memset(root, 0, sizeof(fs_node));
    root->name = kstrdup("initrd");
    root->flags = FS_DIRECTORY;
    root->readdir = initrd_readdir;
    root->finddir = initrd_finddir;

    return root;
}
