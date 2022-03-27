#pragma once

#include <common/types.h>
#include <kernel/forward.h>
#include <stddef.h>

#define PATH_SEPARATOR '/'

#define O_RDONLY 0x1
#define O_WRONLY 0x2
#define O_RDWR (O_RDONLY | O_WRONLY)

enum fs_node_type { FS_FILE, FS_DIRECTORY, FS_CHAR_DEVICE, FS_BLOCK_DEVICE };

typedef struct dirent {
    char* name;
    uint32_t ino;
} dirent;

typedef ssize_t (*read_fn)(fs_node*, off_t offset, size_t size, void* buffer);
typedef ssize_t (*write_fn)(fs_node*, off_t offset, size_t size,
                            const void* buffer);
typedef void (*open_fn)(fs_node*, int flags);
typedef void (*close_fn)(fs_node*);
typedef struct dirent* (*readdir_fn)(fs_node*, size_t index);
typedef fs_node* (*finddir_fn)(fs_node*, const char* name);
typedef uintptr_t (*mmap_fn)(fs_node*, uintptr_t virtual_addr, size_t length,
                             int prot, off_t offset);
typedef int (*ioctl_fn)(fs_node*, int request, void* argp);

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
    mmap_fn mmap;
    ioctl_fn ioctl;
    char* name;
} fs_node;

ssize_t fs_read(fs_node*, off_t offset, size_t size, void* buffer);
ssize_t fs_write(fs_node*, off_t offset, size_t size, const void* buffer);
void fs_open(fs_node*, int flags);
void fs_close(fs_node*);
dirent* fs_readdir(fs_node*, size_t index);
fs_node* fs_finddir(fs_node*, const char* name);
uintptr_t fs_mmap(fs_node*, uintptr_t virtual_addr, size_t length, int prot,
                  off_t offset);
int fs_ioctl(fs_node*, int request, void* argp);

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

int file_descriptor_table_init(file_descriptor_table*);
int file_descriptor_table_clone_from(file_descriptor_table* to,
                                     const file_descriptor_table* from);

void initrd_init(uintptr_t paddr);
fs_node* initrd_create(void);
