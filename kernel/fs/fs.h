#pragma once

#include <common/extra.h>
#include <kernel/api/dirent.h>
#include <kernel/api/sys/stat.h>
#include <kernel/api/sys/types.h>
#include <kernel/api/time.h>
#include <kernel/lock.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>
#include <stdatomic.h>
#include <stdbool.h>

#define PATH_SEPARATOR '/'
#define PATH_SEPARATOR_STR "/"
#define ROOT_DIR PATH_SEPARATOR_STR

typedef struct multiboot_mod_list multiboot_module_t;

void fs_init(const multiboot_module_t* initrd_mod);

// Open file description
struct file {
    struct inode* inode;
    const struct file_ops* fops;
    struct filemap* filemap;
    atomic_int flags;
    uint64_t offset;
    void* private_data;

    struct mutex lock;
    atomic_size_t ref_count;
};

typedef bool (*getdents_callback_fn)(const char* name, ino_t,
                                     unsigned char type, void* ctx);

struct file_ops {
    int (*open)(struct file*);
    int (*close)(struct file*);
    ssize_t (*pread)(struct file*, void* buffer, size_t count, uint64_t offset);
    ssize_t (*pwrite)(struct file*, const void* buffer, size_t count,
                      uint64_t offset);
    int (*ioctl)(struct file*, int request, void* user_argp);
    int (*getdents)(struct file*, getdents_callback_fn, void* ctx);
    short (*poll)(struct file*, short events);
    struct vm_obj* (*mmap)(struct file*);
};

static inline unsigned mode_to_dirent_type(mode_t mode) {
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

extern const struct vm_ops inode_vm_ops;

// inode is fully initialized and ready to be used
#define INODE_READY 0x1

// inode has been modified since the last writeback
#define INODE_DIRTY 0x2

#define INODE_INIT {.vm_obj = {.vm_ops = &inode_vm_ops, .ref_count = 1}}

struct inode {
    struct vm_obj vm_obj;
    struct mount* mount;
    const struct inode_ops* iops;
    const struct file_ops* fops;
    struct filemap* filemap; // Page cache

    ino_t ino;
    mode_t mode;
    dev_t rdev;         // Device number (if this inode is a special file)
    uint64_t size;      // Size in bytes
    uint8_t block_bits; // Block size as 2^block_bits
    blkcnt_t blocks;    // Number of 512 B blocks

    _Atomic(struct inode*) pipe;
    _Atomic(struct inode*) bound_socket;
    atomic_uint flags; // INODE_*

    struct inode* next; // mount->inodes
};

struct inode_ops {
    void (*destroy)(struct inode*);

    struct inode* (*lookup)(struct inode* parent, const char* name);
    int (*link)(struct inode* parent, const char* name, struct inode* child);
    int (*unlink)(struct inode* parent, const char* name);

    ssize_t (*pread)(struct inode*, void* buffer, size_t count,
                     uint64_t offset);
    ssize_t (*pwrite)(struct inode*, const void* buffer, size_t count,
                      uint64_t offset);

    int (*truncate)(struct inode*, uint64_t length);
    int (*sync)(struct inode*);
};

void inode_ref(struct inode*);
void inode_unref(struct inode*);

void inode_lock(struct inode*);
void inode_unlock(struct inode*);

NODISCARD struct inode* inode_lookup(struct inode* parent, const char* name);
NODISCARD int inode_link(struct inode* parent, const char* name,
                         struct inode* child);
NODISCARD int inode_unlink(struct inode* parent, const char* name);

NODISCARD int inode_truncate(struct inode*, uint64_t length);
NODISCARD int inode_sync(struct inode*, uint64_t offset, uint64_t nbytes);

NODISCARD struct file* inode_open(struct inode*, int flags);

struct kstat {
    dev_t st_dev;         /* ID of device containing file */
    ino_t st_ino;         /* Inode number */
    mode_t st_mode;       /* File type and mode */
    nlink_t st_nlink;     /* Number of hard links */
    uid_t st_uid;         /* User ID of owner */
    gid_t st_gid;         /* Group ID of owner */
    dev_t st_rdev;        /* Device ID (if special file) */
    uint64_t st_size;     /* Total size, in bytes */
    blksize_t st_blksize; /* Block size for filesystem I/O */
    blkcnt_t st_blocks;   /* Number of 512 B blocks allocated */

    struct timespec st_atim; /* Time of last access */
    struct timespec st_mtim; /* Time of last modification */
    struct timespec st_ctim; /* Time of last status change */
};

NODISCARD int inode_stat(struct inode*, struct kstat* buf);

struct mount {
    const struct file_system* fs;
    dev_t dev;
    struct inode* root;
    struct inode* inodes; // inode cache
    struct mount* next;
    struct mutex lock;
};

// Marks the given inode as ready to be used, adding it to the mount's inode
// cache.
NODISCARD int mount_commit_inode(struct mount*, struct inode*);

// Creates a new inode for the given mount with the specified mode.
// The file system is responsible for allocating inode numbers.
// The returned inode is committed and ready to be used.
struct inode* mount_create_inode(struct mount*, mode_t);

// Looks up an inode by its inode number in the mount's inode cache.
struct inode* mount_lookup_inode(struct mount*, ino_t);

// Sets the root inode of the mount.
// Panics if the root is already set.
void mount_set_root(struct mount*, struct inode*);

// Writes back all dirty inodes in the mount.
NODISCARD int mount_sync(struct mount*);

void file_ref(struct file*);
void file_unref(struct file*);

NODISCARD ssize_t file_read(struct file*, void* buffer, size_t count);
NODISCARD ssize_t file_pread(struct file*, void* buffer, size_t count,
                             uint64_t offset);
NODISCARD ssize_t file_read_to_end(struct file*, void* buffer, size_t count);
NODISCARD ssize_t file_write(struct file*, const void* buffer, size_t count);
NODISCARD ssize_t file_pwrite(struct file*, const void* buffer, size_t count,
                              uint64_t offset);
NODISCARD ssize_t file_write_all(struct file*, const void* buffer,
                                 size_t count);
NODISCARD int file_truncate(struct file*, uint64_t length);
NODISCARD loff_t file_seek(struct file*, loff_t offset, int whence);
NODISCARD int file_ioctl(struct file*, int request, void* user_argp);
NODISCARD int file_getdents(struct file*, getdents_callback_fn, void* ctx);
NODISCARD short file_poll(struct file*, short events);

NODISCARD struct vm_obj* file_mmap(struct file*);

NODISCARD int file_block(struct file*, bool (*unblock)(struct file*),
                         int flags);

// Disallow mounting this file system from user space
#define FILE_SYSTEM_KERNEL_ONLY 0x1

struct file_system {
    char name[16];
    const struct fs_ops* fs_ops;
    unsigned flags;
    struct file_system* next;
};

struct fs_ops {
    struct mount* (*mount)(const char* source);
    struct inode* (*create_inode)(struct mount*, mode_t);
};

extern struct file_system* file_systems;

NODISCARD int file_system_register(struct file_system*);
const struct file_system* file_system_find(const char* name);
struct mount* file_system_mount(const struct file_system*, const char* source);

struct path* vfs_get_root(void);

NODISCARD int vfs_mount(const struct file_system*, const char* source,
                        const char* target);
NODISCARD int vfs_mount_at(const struct file_system*, const struct path* base,
                           const char* source, const char* target);

// Return a path even if the last component of the path does not exist.
// The last component of the returned path will have NULL inode in this case.
#define O_ALLOW_NOENT 0x4000

// When combined with O_NOFOLLOW, do not return an error if the last component
// of the path is a symbolic link, and return the symlink itself.
#define O_NOFOLLOW_NOERROR 0x2000

NODISCARD struct file* vfs_open(const char* pathname, int flags, mode_t mode);
NODISCARD struct file* vfs_open_at(const struct path* base,
                                   const char* pathname, int flags,
                                   mode_t mode);
NODISCARD int vfs_stat(const char* pathname, struct kstat* buf, int flags);
NODISCARD int vfs_stat_at(const struct path* base, const char* pathname,
                          struct kstat* buf, int flags);
NODISCARD struct inode* vfs_create(const char* pathname, mode_t mode);
NODISCARD struct inode* vfs_create_at(const struct path* base,
                                      const char* pathname, mode_t mode);

struct path* vfs_resolve_path(const char* pathname, int flags);
struct path* vfs_resolve_path_at(const struct path* base, const char* pathname,
                                 int flags);

// Writes back all dirty inodes.
NODISCARD int vfs_sync(void);

struct inode* pipe_create(void);
