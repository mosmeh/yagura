#pragma once

#include <kernel/api/types.h>
#include <kernel/forward.h>
#include <stddef.h>

#define PATH_SEPARATOR '/'

#define FD_TABLE_CAPACITY 1024

typedef struct file_description {
    fs_node* node;
    off_t offset;
} file_description;

typedef struct file_descriptor_table {
    file_description* entries;
} file_descriptor_table;

int file_descriptor_table_init(file_descriptor_table*);
int file_descriptor_table_clone_from(file_descriptor_table* to,
                                     const file_descriptor_table* from);

typedef fs_node* (*lookup_fn)(fs_node*, const char* name);
typedef fs_node* (*create_child_fn)(fs_node*, const char* name, mode_t mode);
typedef int (*open_fn)(fs_node*, int flags, mode_t mode);

typedef int (*close_fn)(file_description*);
typedef ssize_t (*read_fn)(file_description*, void* buffer, size_t count);
typedef ssize_t (*write_fn)(file_description*, const void* buffer,
                            size_t count);
typedef uintptr_t (*mmap_fn)(file_description*, uintptr_t addr, size_t length,
                             int prot, off_t offset);
typedef int (*truncate_fn)(file_description*, off_t length);
typedef int (*ioctl_fn)(file_description*, int request, void* argp);
typedef long (*readdir_fn)(file_description*, void* dirp, unsigned int count);

typedef struct fs_node {
    char* name;
    lookup_fn lookup;
    create_child_fn create_child;
    open_fn open;
    close_fn close;
    read_fn read;
    write_fn write;
    mmap_fn mmap;
    truncate_fn truncate;
    ioctl_fn ioctl;
    readdir_fn readdir;
    mode_t mode;
    union {
        ino_t ino;
        uint32_t device;
        void* ptr;
    };
} fs_node;

fs_node* fs_lookup(fs_node*, const char* name);
fs_node* fs_create_child(fs_node*, const char* name, mode_t mode);
int fs_open(fs_node*, int flags, mode_t mode);

int fs_close(file_description*);
ssize_t fs_read(file_description*, void* buffer, size_t count);
ssize_t fs_write(file_description*, const void* buffer, size_t count);
uintptr_t fs_mmap(file_description*, uintptr_t addr, size_t length, int prot,
                  off_t offset);
int fs_truncate(file_description*, off_t length);
int fs_ioctl(file_description*, int request, void* argp);
long fs_readdir(file_description*, void* dirp, unsigned int count);

void vfs_init(void);
void vfs_mount(char* path, fs_node* fs);
fs_node* vfs_open(const char* pathname, int flags, mode_t mode);

uint8_t mode_to_dirent_type(mode_t);

void initrd_init(uintptr_t addr);
fs_node* initrd_create(void);

fs_node* tmpfs_create(void);
