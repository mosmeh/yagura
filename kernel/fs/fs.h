#pragma once

#include <common/extra.h>
#include <kernel/api/sys/stat.h>
#include <kernel/api/sys/types.h>
#include <kernel/lock.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

#define PATH_SEPARATOR '/'
#define PATH_SEPARATOR_STR "/"
#define ROOT_DIR PATH_SEPARATOR_STR

#define OPEN_MAX 1024

typedef struct unix_socket unix_socket;
typedef struct multiboot_info multiboot_info_t;
typedef struct multiboot_mod_list multiboot_module_t;

typedef struct file_description {
    mutex offset_lock;
    struct inode* inode;
    atomic_int flags;
    off_t offset;
    void* private_data;
    atomic_size_t ref_count;
} file_description;

typedef struct file_descriptor_table {
    file_description** entries;
} file_descriptor_table;

NODISCARD int file_descriptor_table_init(file_descriptor_table*);
void file_descriptor_table_destroy(file_descriptor_table*);
NODISCARD int
file_descriptor_table_clone_from(file_descriptor_table* to,
                                 const file_descriptor_table* from);

typedef bool (*getdents_callback_fn)(const char* name, uint8_t type, void* ctx);

typedef struct file_ops {
    void (*destroy_inode)(struct inode*);

    struct inode* (*lookup_child)(struct inode*, const char* name);
    struct inode* (*create_child)(struct inode*, const char* name, mode_t mode);
    int (*link_child)(struct inode*, const char* name, struct inode* child);
    struct inode* (*unlink_child)(struct inode*, const char* name);
    int (*open)(file_description*, int flags, mode_t mode);
    int (*stat)(struct inode*, struct stat* buf);

    int (*close)(file_description*);
    ssize_t (*read)(file_description*, void* buffer, size_t count);
    ssize_t (*write)(file_description*, const void* buffer, size_t count);
    int (*mmap)(file_description*, uintptr_t addr, size_t length, off_t offset,
                uint16_t page_flags);
    int (*truncate)(file_description*, off_t length);
    int (*ioctl)(file_description*, int request, void* user_argp);
    int (*getdents)(file_description*, getdents_callback_fn callback,
                    void* ctx);
    short (*poll)(file_description*, short events);
} file_ops;

struct inode {
    file_ops* fops;
    dev_t dev;  // Device number of device containing this inode
    dev_t rdev; // Device number (if this inode is a special file)
    _Atomic(unix_socket*) bound_socket;
    _Atomic(nlink_t) num_links;
    atomic_size_t ref_count;
    mode_t mode;
};

void inode_ref(struct inode*);
void inode_unref(struct inode*);

void inode_destroy(struct inode*);
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
NODISCARD int file_description_mmap(file_description*, uintptr_t addr,
                                    size_t length, off_t offset,
                                    uint16_t page_flags);
NODISCARD int file_description_truncate(file_description*, off_t length);
NODISCARD off_t file_description_seek(file_description*, off_t offset,
                                      int whence);
NODISCARD int file_description_ioctl(file_description*, int request,
                                     void* user_argp);
NODISCARD int file_description_getdents(file_description*, getdents_callback_fn,
                                        void* ctx);

NODISCARD int file_description_block(file_description*,
                                     bool (*should_unblock)(file_description*));

void vfs_init(void);
void vfs_populate_root_fs(const multiboot_module_t* initrd_mod);
struct inode* vfs_get_root(void);
NODISCARD int vfs_mount(const char* path, struct inode* fs_root);

NODISCARD int vfs_register_device(struct inode* device);
struct inode* vfs_get_device(dev_t);
dev_t vfs_generate_unnamed_device_number(void);

NODISCARD file_description* vfs_open(const char* pathname, int flags,
                                     mode_t mode);
NODISCARD int vfs_stat(const char* pathname, struct stat* buf);
NODISCARD struct inode* vfs_create(const char* pathname, mode_t mode);

char* vfs_canonicalize_path(const char* pathname);
struct inode* vfs_resolve_path(const char* pathname, struct inode** out_parent,
                               char** out_basename);

uint8_t mode_to_dirent_type(mode_t);

struct inode* fifo_create(void);

struct inode* tmpfs_create_root(void);
struct inode* procfs_create_root(void);
