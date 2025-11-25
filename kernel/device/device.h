#pragma once

#include <common/extra.h>
#include <kernel/api/sys/types.h>
#include <kernel/fs/fs.h>

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
#define SECTOR_SIZE (1 << SECTOR_SHIFT)

#define BLOCK_DEV_INIT {.vfs_inode = INODE_INIT}

struct block_dev {
    struct inode vfs_inode;
    char name[16];
    dev_t dev;
    const struct block_ops* bops;
    uint8_t block_bits; // Block size as 2^block_bits
    size_t num_blocks;
};

struct block_ops {
    int (*read)(struct block_dev*, void* buffer, uint64_t index,
                uint64_t nblocks);
    int (*write)(struct block_dev*, const void* buffer, uint64_t index,
                 uint64_t nblocks);
};

extern const struct file_ops block_dev_fops;

NODISCARD int block_dev_register(struct block_dev*);
struct block_dev* block_dev_get(dev_t);

void block_dev_lock(struct block_dev*);
void block_dev_unlock(struct block_dev*);
