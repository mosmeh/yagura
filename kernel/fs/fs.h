#pragma once

#include <kernel/api/types.h>
#include <kernel/forward.h>
#include <stdbool.h>
#include <stddef.h>

#define PATH_SEPARATOR '/'

#define FD_TABLE_CAPACITY 1024

typedef struct file_description {
    struct file* file;
    off_t offset;
    int flags;
} file_description;

typedef struct file_descriptor_table {
    file_description** entries;
} file_descriptor_table;

int file_descriptor_table_init(file_descriptor_table*);
int file_descriptor_table_clone_from(file_descriptor_table* to,
                                     const file_descriptor_table* from);

typedef struct file* (*lookup_fn)(struct file*, const char* name);
typedef struct file* (*create_child_fn)(struct file*, const char* name,
                                        mode_t mode);
typedef int (*open_fn)(struct file*, int flags, mode_t mode);

typedef int (*close_fn)(file_description*);
typedef ssize_t (*read_fn)(file_description*, void* buffer, size_t count);
typedef ssize_t (*write_fn)(file_description*, const void* buffer,
                            size_t count);
typedef uintptr_t (*mmap_fn)(file_description*, uintptr_t addr, size_t length,
                             int prot, off_t offset, bool shared);
typedef int (*truncate_fn)(file_description*, off_t length);
typedef int (*ioctl_fn)(file_description*, int request, void* argp);
typedef long (*readdir_fn)(file_description*, void* dirp, unsigned int count);

struct file {
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
    unix_socket* bound_socket;
};

struct file* fs_lookup(struct file*, const char* name);
struct file* fs_create_child(struct file*, const char* name, mode_t mode);
int fs_open(struct file*, int flags, mode_t mode);

int fs_close(file_description*);
ssize_t fs_read(file_description*, void* buffer, size_t count);
ssize_t fs_write(file_description*, const void* buffer, size_t count);
uintptr_t fs_mmap(file_description*, uintptr_t addr, size_t length, int prot,
                  off_t offset, bool shared);
int fs_truncate(file_description*, off_t length);
int fs_ioctl(file_description*, int request, void* argp);
long fs_readdir(file_description*, void* dirp, unsigned int count);

void vfs_init(void);
void vfs_mount(const char* path, struct file* fs);
file_description* vfs_open(const char* pathname, int flags, mode_t mode);

uint8_t mode_to_dirent_type(mode_t);

void initrd_init(uintptr_t addr);
struct file* initrd_create_root(void);

struct file* tmpfs_create_root(void);
struct file* shmfs_create_root(void);
