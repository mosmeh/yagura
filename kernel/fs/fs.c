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

struct file* fs_lookup(struct file* file, const char* name) {
    if (!file->lookup || !S_ISDIR(file->mode))
        return ERR_PTR(-ENOTDIR);
    return file->lookup(file, name);
}

struct file* fs_create_child(struct file* file, const char* name, mode_t mode) {
    if (!file->create_child || !S_ISDIR(file->mode))
        return ERR_PTR(-ENOTDIR);
    if (!(mode & S_IFMT))
        mode |= S_IFREG;
    return file->create_child(file, name, mode);
}

int fs_open(struct file* file, int flags, mode_t mode) {
    if (file->open)
        return file->open(file, flags, mode);
    return 0;
}

int fs_close(file_description* desc) {
    struct file* file = desc->file;
    if (file->close)
        return file->close(desc);
    return 0;
}

ssize_t fs_read(file_description* desc, void* buffer, size_t count) {
    struct file* file = desc->file;
    if (!file->read)
        return 0;
    return file->read(desc, buffer, count);
}

ssize_t fs_write(file_description* desc, const void* buffer, size_t count) {
    struct file* file = desc->file;
    if (!file->write)
        return 0;
    return file->write(desc, buffer, count);
}

uintptr_t fs_mmap(file_description* desc, uintptr_t vaddr, size_t length,
                  int prot, off_t offset) {
    struct file* file = desc->file;
    if (!file->mmap)
        return -ENODEV;
    return file->mmap(desc, vaddr, length, prot, offset);
}

int fs_truncate(file_description* desc, off_t length) {
    struct file* file = desc->file;
    if (S_ISDIR(file->mode))
        return -EISDIR;
    if (!file->truncate)
        return -EROFS;
    return file->truncate(desc, length);
}

int fs_ioctl(file_description* desc, int request, void* argp) {
    struct file* file = desc->file;
    if (!file->ioctl)
        return -ENOTTY;
    file->ioctl(desc, request, argp);
    return 0;
}

long fs_readdir(file_description* desc, void* dirp, unsigned int count) {
    struct file* file = desc->file;
    if (!file->readdir || !S_ISDIR(file->mode))
        return -ENOTDIR;
    return file->readdir(desc, dirp, count);
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
    UNREACHABLE();
}
