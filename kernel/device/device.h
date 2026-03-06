#pragma once

#include <kernel/api/sys/types.h>
#include <kernel/fs/inode.h>

void device_init(void);

struct char_dev {
    char name[16];
    dev_t dev;
    const struct file_ops* fops;
    struct char_dev* next;
};

extern const struct file_ops char_dev_fops;

NODISCARD int char_dev_register(struct char_dev*);
struct char_dev* char_dev_get(dev_t);
struct char_dev* char_dev_find_by_name(const char*);

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

DEFINE_LOCKED(block_dev, struct block_dev*, inode, vfs_inode)
DEFINE_REFCOUNTED_SUB(block_dev, struct block_dev*, inode, vfs_inode)

extern const struct file_ops block_dev_fops;

NODISCARD int block_dev_register(struct block_dev*);
struct block_dev* block_dev_get(dev_t);

NODISCARD
int block_dev_read(struct block_dev*, struct page*, size_t block_index);
NODISCARD
int block_dev_write(struct block_dev*, struct page*, size_t block_index);
