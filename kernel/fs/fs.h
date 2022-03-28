#pragma once

#include <common/types.h>
#include <kernel/forward.h>
#include <stddef.h>

#define PATH_SEPARATOR '/'

#define O_RDONLY 0x1
#define O_WRONLY 0x2
#define O_RDWR (O_RDONLY | O_WRONLY)

enum fs_node_type { FS_INODE, FS_DIRECTORY, FS_CHAR_DEVICE, FS_BLOCK_DEVICE };

#define FD_TABLE_CAPACITY 1024

typedef struct file_description {
    fs_node* node;
    uint32_t offset;
} file_description;

typedef struct file_descriptor_table {
    file_description* entries;
} file_descriptor_table;

int file_descriptor_table_init(file_descriptor_table*);
int file_descriptor_table_clone_from(file_descriptor_table* to,
                                     const file_descriptor_table* from);

typedef struct dirent {
    uint32_t type;
    ino_t ino;
    size_t record_len;
    char name[];
} dirent;

typedef fs_node* (*lookup_fn)(fs_node*, const char* name);
typedef void (*open_fn)(fs_node*, int flags);

typedef void (*close_fn)(file_description*);
typedef ssize_t (*read_fn)(file_description*, void* buffer, size_t count);
typedef ssize_t (*write_fn)(file_description*, const void* buffer,
                            size_t count);
typedef uintptr_t (*mmap_fn)(file_description*, uintptr_t addr, size_t length,
                             int prot, off_t offset);
typedef int (*ioctl_fn)(file_description*, int request, void* argp);
typedef long (*readdir_fn)(file_description*, void* dirp, unsigned int count);

typedef struct fs_node {
    char* name;
    uint32_t type;
    lookup_fn lookup;
    open_fn open;
    close_fn close;
    read_fn read;
    write_fn write;
    mmap_fn mmap;
    ioctl_fn ioctl;
    readdir_fn readdir;
    union {
        ino_t ino;
        uint32_t device;
    };
} fs_node;

fs_node* fs_lookup(fs_node*, const char* name);
void fs_open(fs_node*, int flags);

void fs_close(file_description*);
ssize_t fs_read(file_description*, void* buffer, size_t size);
ssize_t fs_write(file_description*, const void* buffer, size_t size);
uintptr_t fs_mmap(file_description*, uintptr_t addr, size_t length, int prot,
                  off_t offset);
int fs_ioctl(file_description*, int request, void* argp);
long fs_readdir(file_description*, void* dirp, unsigned int count);

void vfs_init(void);
void vfs_mount(char* path, fs_node* fs);
fs_node* vfs_find_node_by_pathname(const char* pathname);

void initrd_init(uintptr_t addr);
fs_node* initrd_create(void);
