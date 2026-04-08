#pragma once

#include <kernel/api/dirent.h>
#include <kernel/api/sys/stat.h>
#include <kernel/api/sys/types.h>
#include <kernel/api/time.h>
#include <kernel/memory/vm.h>

extern const struct vm_ops inode_vm_ops;

// inode is fully initialized and ready to be used
#define INODE_READY 0x1

// inode has been modified since the last writeback
#define INODE_DIRTY 0x2

#define INODE_INIT                                                             \
    {                                                                          \
        .vm_obj = {.vm_ops = &inode_vm_ops, .refcount = REFCOUNT_INIT_ONE }    \
    }

struct inode {
    struct vm_obj vm_obj;
    struct mount* mount;
    const struct inode_ops* iops;
    const struct file_ops* fops;
    struct filemap* filemap; // Page cache

    ino_t ino;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    dev_t rdev;         // Device number (if this inode is a special file)
    uint64_t size;      // Size in bytes
    uint8_t block_bits; // Block size as 2^block_bits
    blkcnt_t blocks;    // Number of 512 B blocks

    _Atomic(struct inode*) pipe;
    _Atomic(struct inode*) bound_socket;
    _Atomic(unsigned int) flags; // INODE_*

    struct tree_node tree_node; // mount->inodes
};

struct inode_ops {
    void (*destroy)(struct inode*);

    NODISCARD struct inode* (*lookup)(struct inode* parent, const char* name);
    NODISCARD int (*link)(struct inode* parent, const char* name,
                          struct inode* child);
    NODISCARD int (*unlink)(struct inode* parent, const char* name);

    NODISCARD int (*read)(struct inode*, struct page*, size_t page_index);
    NODISCARD int (*write)(struct inode*, struct page*, size_t page_index);

    NODISCARD int (*truncate)(struct inode*, uint64_t length);
    NODISCARD int (*sync)(struct inode*);
};

DEFINE_LOCKED(inode, struct inode, vm_obj, vm_obj)
DEFINE_REFCOUNTED_SUB(inode, struct inode, vm_obj, vm_obj)

NODISCARD struct inode* inode_lookup(struct inode* parent, const char* name);
NODISCARD int inode_link(struct inode* parent, const char* name,
                         struct inode* child);
NODISCARD int inode_unlink(struct inode* parent, const char* name);

NODISCARD int inode_truncate(struct inode*, uint64_t length);
NODISCARD int inode_sync(struct inode*, uint64_t offset, uint64_t nbytes);

NODISCARD struct file* inode_open(struct inode*, int flags);

#define S_IRUGO (S_IRUSR | S_IRGRP | S_IROTH)
#define S_IWUGO (S_IWUSR | S_IWGRP | S_IWOTH)
#define S_IXUGO (S_IXUSR | S_IXGRP | S_IXOTH)

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

struct filemap {
    struct inode* inode;
    struct tree pages;
};
