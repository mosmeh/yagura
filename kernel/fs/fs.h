#pragma once

#include <common/extra.h>
#include <kernel/api/sys/stat.h>
#include <kernel/api/sys/types.h>
#include <kernel/forward.h>
#include <stdbool.h>
#include <stddef.h>

#define PATH_SEPARATOR '/'
#define PATH_SEPARATOR_STR "/"
#define ROOT_DIR PATH_SEPARATOR_STR

#define OPEN_MAX 1024

typedef struct file_description {
    struct file* file;
    off_t offset;
    int flags;
    size_t ref_count;
} file_description;

typedef struct file_descriptor_table {
    file_description** entries;
} file_descriptor_table;

NODISCARD int file_descriptor_table_init(file_descriptor_table*);
NODISCARD int
file_descriptor_table_clone_from(file_descriptor_table* to,
                                 const file_descriptor_table* from);

typedef struct file* (*lookup_fn)(struct file*, const char* name);
typedef struct file* (*create_child_fn)(struct file*, const char* name,
                                        mode_t mode);
typedef int (*open_fn)(struct file*, int flags, mode_t mode);
typedef int (*stat_fn)(struct file*, struct stat* buf);

typedef int (*close_fn)(file_description*);
typedef ssize_t (*read_fn)(file_description*, void* buffer, size_t count);
typedef ssize_t (*write_fn)(file_description*, const void* buffer,
                            size_t count);
typedef uintptr_t (*mmap_fn)(file_description*, uintptr_t addr, size_t length,
                             off_t offset, uint16_t page_flags);
typedef int (*truncate_fn)(file_description*, off_t length);
typedef int (*ioctl_fn)(file_description*, int request, void* argp);
typedef long (*readdir_fn)(file_description*, void* dirp, unsigned int count);

typedef struct file_ops {
    lookup_fn lookup;
    create_child_fn create_child;
    open_fn open;
    stat_fn stat;
    close_fn close;
    read_fn read;
    write_fn write;
    mmap_fn mmap;
    truncate_fn truncate;
    ioctl_fn ioctl;
    readdir_fn readdir;
} file_ops;

struct file {
    char* name;
    file_ops* fops;
    mode_t mode;
    dev_t device_id;
    unix_socket* bound_socket;
};

struct file* fs_lookup(struct file*, const char* name);
struct file* fs_create_child(struct file*, const char* name, mode_t mode);
file_description* fs_open(struct file*, int flags, mode_t mode);
NODISCARD int fs_stat(struct file*, struct stat* buf);

int fs_close(file_description*);
NODISCARD ssize_t fs_read(file_description*, void* buffer, size_t count);
NODISCARD ssize_t fs_write(file_description*, const void* buffer, size_t count);
NODISCARD uintptr_t fs_mmap(file_description*, uintptr_t addr, size_t length,
                            off_t offset, uint16_t page_flags);
NODISCARD int fs_truncate(file_description*, off_t length);
NODISCARD off_t fs_lseek(file_description*, off_t offset, int whence);
NODISCARD int fs_ioctl(file_description*, int request, void* argp);
NODISCARD long fs_readdir(file_description*, void* dirp, unsigned int count);

NODISCARD int fs_block(file_description*,
                       bool (*should_unblock)(file_description*));

NODISCARD int vfs_mount(const char* path, struct file* root_file);
NODISCARD int vfs_register_device(struct file* device_file);
NODISCARD file_description* vfs_open(const char* pathname, int flags,
                                     mode_t mode);
NODISCARD int vfs_stat(const char* pathname, struct stat* buf);
NODISCARD struct file* vfs_create(const char* pathname, mode_t mode);
char* vfs_canonicalize_path(const char* pathname, const char* parent_path);
struct file* vfs_resolve_path(const char* pathname, const char* parent_path,
                              struct file** out_parent,
                              const char** out_basename);

uint8_t mode_to_dirent_type(mode_t);

struct fifo* fifo_create(void);

void initrd_populate_root_fs(uintptr_t physical_addr, size_t size);

struct file* tmpfs_create_root(void);
struct file* procfs_create_root(void);
