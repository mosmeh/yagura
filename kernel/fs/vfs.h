#pragma once

#include <kernel/api/time.h>
#include <kernel/lock.h>
#include <kernel/memory/phys.h>

struct path;
struct kstat;
struct vec;

// mount is fully initialized and ready to be used
#define MOUNT_READY 0x1

struct mount {
    const struct file_system* fs;
    dev_t dev;
    struct inode* root;
    struct inode* inodes; // inode cache
    unsigned flags;
    struct mount* next;
    struct mutex lock;
};

DEFINE_LOCKED(mount, struct mount*, mutex, lock)

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

// Disallow mounting this file system from user space
#define FILE_SYSTEM_KERNEL_ONLY 0x1

struct file_system {
    char name[16];

    struct mount* (*mount)(const char* source);
    struct inode* (*create_inode)(struct mount*, mode_t);

    unsigned flags;
    struct file_system* next;
};

NODISCARD int file_system_register(struct file_system*);
const struct file_system* file_system_find(const char* name);
struct mount* file_system_mount(const struct file_system*, const char* source);

NODISCARD int vfs_mount(const struct file_system*, const char* source,
                        const char* target);
NODISCARD int vfs_mount_at(const struct file_system*, const struct path* base,
                           const char* source, const char* target);

// Return a path even if the last component of the path does not exist.
// The last component of the returned path will have NULL inode in this case.
#define O_ALLOW_NOENT 0x20000000

// When combined with O_NOFOLLOW, do not return an error if the last component
// of the path is a symbolic link, and return the symlink itself.
#define O_NOFOLLOW_NOERROR 0x40000000

#define O_KERNEL_INTERNAL_MASK (O_ALLOW_NOENT | O_NOFOLLOW_NOERROR)

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

void initramfs_populate_root_fs(phys_addr_t phys_addr, size_t size);

NODISCARD int devtmpfs_mknod(const char* name, mode_t mode, dev_t dev);

struct inode* pipe_create(void);

int proc_print_filesystems(struct file*, struct vec*);
int proc_print_mounts(struct file*, struct vec*);
