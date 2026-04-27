#pragma once

#include <kernel/fs/inode.h>

#define SECTOR_SHIFT 9
#define SECTOR_SIZE (1UL << SECTOR_SHIFT)

#define BLOCK_DEV_INIT {.vfs_inode = INODE_INIT}

struct block_dev {
    struct inode vfs_inode;
    char name[16];
    dev_t dev;
    const struct block_ops* bops;
    uint8_t block_bits; // Block size as 2^block_bits
    uint64_t num_blocks;
};

struct block_ops {
    NODISCARD int (*read)(struct block_dev*, phys_addr_t buffer, uint64_t index,
                          size_t nblocks);
    NODISCARD int (*write)(struct block_dev*, phys_addr_t buffer,
                           uint64_t index, size_t nblocks);
    NODISCARD int (*flush)(struct block_dev*);
};

DEFINE_LOCKED(block_dev, struct block_dev, inode, vfs_inode)
DEFINE_REFCOUNTED_SUB(block_dev, struct block_dev, inode, vfs_inode)

extern const struct file_ops block_dev_fops;

NODISCARD int block_dev_register(struct block_dev*);
struct block_dev* block_dev_get(dev_t);
