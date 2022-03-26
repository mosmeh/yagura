#pragma once

#include <common/types.h>
#include <kernel/forward.h>
#include <stddef.h>

#define PATH_SEPARATOR '/'

enum fs_node_type { FS_FILE, FS_DIRECTORY, FS_CHARDEVICE, FS_BLOCKDEVICE };

typedef struct dirent {
    char* name;
    uint32_t ino;
} dirent;

typedef uint32_t (*read_fn)(fs_node*, off_t offset, size_t size, void* buffer);
typedef uint32_t (*write_fn)(fs_node*, off_t offset, size_t size,
                             const void* buffer);
typedef void (*open_fn)(fs_node*, int flags);
typedef void (*close_fn)(fs_node*);
typedef struct dirent* (*readdir_fn)(fs_node*, size_t index);
typedef fs_node* (*finddir_fn)(fs_node*, const char* name);

typedef struct fs_node {
    uint32_t flags;
    uint32_t inode;
    uint32_t length;
    read_fn read;
    write_fn write;
    open_fn open;
    close_fn close;
    readdir_fn readdir;
    finddir_fn finddir;
    char* name;
} fs_node;

uint32_t fs_read(fs_node* node, off_t offset, size_t size, void* buffer);
uint32_t fs_write(fs_node* node, off_t offset, size_t size, const void* buffer);
void fs_open(fs_node* node, int flags);
void fs_close(fs_node* node);
dirent* fs_readdir(fs_node* node, size_t index);
fs_node* fs_finddir(fs_node* node, const char* name);

void vfs_init(void);
void vfs_mount(char* path, fs_node* fs);
fs_node* vfs_find_by_pathname(const char* pathname);

#define FD_TABLE_CAPACITY 1024

typedef struct file_description {
    fs_node* node;
    uint32_t offset;
} file_description;

typedef struct file_descriptor_table {
    file_description* entries;
} file_descriptor_table;

void initrd_init(uintptr_t paddr);
fs_node* initrd_create(void);
