#include "fs.h"
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/err.h>
#include <kernel/api/stat.h>
#include <kernel/kmalloc.h>
#include <kernel/panic.h>

int file_descriptor_table_init(file_descriptor_table* table) {
    table->entries = kmalloc(FD_TABLE_CAPACITY * sizeof(file_description));
    if (!table->entries)
        return -ENOMEM;

    memset(table->entries, 0, FD_TABLE_CAPACITY * sizeof(file_description));
    return 0;
}

int file_descriptor_table_clone_from(file_descriptor_table* to,
                                     const file_descriptor_table* from) {
    to->entries = kmalloc(FD_TABLE_CAPACITY * sizeof(file_description));
    if (!to->entries)
        return -ENOMEM;

    memcpy(to->entries, from->entries,
           FD_TABLE_CAPACITY * sizeof(file_description));
    return 0;
}

fs_node* fs_lookup(fs_node* node, const char* name) {
    if (!node->lookup || !S_ISDIR(node->mode))
        return ERR_PTR(-ENOTDIR);
    return node->lookup(node, name);
}

fs_node* fs_create_child(fs_node* node, const char* name, mode_t mode) {
    if (!node->create_child || !S_ISDIR(node->mode))
        return ERR_PTR(-ENOTDIR);
    if (!(mode & S_IFMT))
        mode |= S_IFREG;
    return node->create_child(node, name, mode);
}

int fs_open(fs_node* node, int flags, mode_t mode) {
    if (node->open)
        return node->open(node, flags, mode);
    return 0;
}

int fs_close(file_description* desc) {
    fs_node* node = desc->node;
    if (node->close)
        return node->close(desc);
    return 0;
}

ssize_t fs_read(file_description* desc, void* buffer, size_t count) {
    fs_node* node = desc->node;
    if (!node->read)
        return 0;
    return node->read(desc, buffer, count);
}

ssize_t fs_write(file_description* desc, const void* buffer, size_t count) {
    fs_node* node = desc->node;
    if (!node->write)
        return 0;
    return node->write(desc, buffer, count);
}

uintptr_t fs_mmap(file_description* desc, uintptr_t vaddr, size_t length,
                  int prot, off_t offset) {
    fs_node* node = desc->node;
    if (!node->mmap)
        return -ENODEV;
    return node->mmap(desc, vaddr, length, prot, offset);
}

int fs_truncate(file_description* desc, off_t length) {
    fs_node* node = desc->node;
    if (S_ISDIR(node->mode))
        return -EISDIR;
    if (!node->truncate)
        return -EROFS;
    return node->truncate(desc, length);
}

int fs_ioctl(file_description* desc, int request, void* argp) {
    fs_node* node = desc->node;
    if (!node->ioctl)
        return -ENOTTY;
    node->ioctl(desc, request, argp);
    return 0;
}

long fs_readdir(file_description* desc, void* dirp, unsigned int count) {
    fs_node* node = desc->node;
    if (!node->readdir || !S_ISDIR(node->mode))
        return -ENOTDIR;
    return node->readdir(desc, dirp, count);
}

uint8_t mode_to_dirent_type(mode_t mode) {
    switch (mode & S_IFMT) {
    case S_IFDIR:
        return DT_DIR;
    case S_IFCHR:
        return DT_CHR;
    case S_IFBLK:
        return DT_BLK;
    case S_IFREG:
        return DT_REG;
    case S_IFIFO:
        return DT_FIFO;
    case S_IFLNK:
        return DT_LNK;
    case S_IFSOCK:
        return DT_SOCK;
    }
    KUNREACHABLE();
}
