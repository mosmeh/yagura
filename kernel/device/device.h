#pragma once

#include <common/extra.h>
#include <kernel/api/sys/types.h>

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

struct block_dev {
    char name[16];
    struct inode* inode;
    struct block_dev* next;
};

NODISCARD int block_dev_register(struct block_dev*);
struct block_dev* block_dev_get(dev_t);
dev_t block_dev_generate_unnamed_device_number(void);
