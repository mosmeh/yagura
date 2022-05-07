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
    struct inode* inode;
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

typedef struct inode* (*lookup_child_fn)(struct inode*, const char* name);
typedef struct inode* (*create_child_fn)(struct inode*, const char* name,
                                         mode_t mode);
typedef int (*link_child_fn)(struct inode*, const char* name,
                             struct inode* child);
typedef struct inode* (*unlink_child_fn)(struct inode*, const char* name);
typedef int (*open_fn)(struct inode*, int flags, mode_t mode);
typedef int (*stat_fn)(struct inode*, struct stat* buf);

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
    lookup_child_fn lookup_child;
    create_child_fn create_child;
    link_child_fn link_child;
    unlink_child_fn unlink_child;
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

struct inode {
    file_ops* fops;
    nlink_t num_links;
    dev_t device_id;
    unix_socket* bound_socket;
    mode_t mode;
};

NODISCARD struct inode* inode_lookup_child(struct inode*, const char* name);
NODISCARD struct inode* inode_create_child(struct inode*, const char* name,
                                           mode_t mode);
NODISCARD int inode_link_child(struct inode*, const char* name,
                               struct inode* child);
NODISCARD int inode_unlink_child(struct inode*, const char* name);
NODISCARD file_description* inode_open(struct inode*, int flags, mode_t mode);
NODISCARD int inode_stat(struct inode*, struct stat* buf);

int file_description_close(file_description*);
NODISCARD ssize_t file_description_read(file_description*, void* buffer,
                                        size_t count);
NODISCARD ssize_t file_description_write(file_description*, const void* buffer,
                                         size_t count);
NODISCARD uintptr_t file_description_mmap(file_description*, uintptr_t addr,
                                          size_t length, off_t offset,
                                          uint16_t page_flags);
NODISCARD int file_description_truncate(file_description*, off_t length);
NODISCARD off_t file_description_lseek(file_description*, off_t offset,
                                       int whence);
NODISCARD int file_description_ioctl(file_description*, int request,
                                     void* argp);
NODISCARD long file_description_readdir(file_description*, void* dirp,
                                        unsigned int count);

NODISCARD int file_description_block(file_description*,
                                     bool (*should_unblock)(file_description*));

NODISCARD int vfs_mount(const char* path, struct inode* fs_root);
NODISCARD int vfs_register_device(struct inode* device);
NODISCARD file_description* vfs_open(const char* pathname, int flags,
                                     mode_t mode);
NODISCARD int vfs_stat(const char* pathname, struct stat* buf);
NODISCARD struct inode* vfs_create(const char* pathname, mode_t mode);
char* vfs_canonicalize_path(const char* pathname);
struct inode* vfs_resolve_path(const char* pathname, struct inode** out_parent,
                               const char** out_basename);

uint8_t mode_to_dirent_type(mode_t);

struct inode* fifo_create(void);

void initrd_populate_root_fs(uintptr_t physical_addr, size_t size);

struct inode* tmpfs_create_root(void);
