#pragma once

#include <common/macros.h>
#include <kernel/api/sys/types.h>

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
