#include "device.h"
#include <common/string.h>
#include <kernel/api/errno.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>

void pseudo_devices_init(void);

void device_init(void) { pseudo_devices_init(); }

static struct char_dev* char_devices;

int char_dev_register(struct char_dev* char_dev) {
    ASSERT(!char_dev->next);
    for (struct char_dev* it = char_devices; it; it = it->next) {
        if (it->dev == char_dev->dev)
            return -EEXIST;
        if (!strcmp(it->name, char_dev->name))
            return -EEXIST;
    }
    char_dev->next = char_devices;
    char_devices = char_dev;
    kprintf("char_dev: registered %s %u,%u\n", char_dev->name,
            major(char_dev->dev), minor(char_dev->dev));
    return 0;
}

struct char_dev* char_dev_get(dev_t rdev) {
    for (struct char_dev* it = char_devices; it; it = it->next) {
        if (it->dev == rdev)
            return it;
    }
    return NULL;
}

struct char_dev* char_dev_find_by_name(const char* name) {
    for (struct char_dev* it = char_devices; it; it = it->next) {
        if (!strcmp(it->name, name))
            return it;
    }
    return NULL;
}

static int char_dev_open(struct file* file) {
    struct char_dev* char_dev = char_dev_get(file->inode->rdev);
    if (!char_dev)
        return -ENODEV;
    file->fops = char_dev->fops;
    if (file->fops->open)
        return file->fops->open(file);
    return 0;
}

const struct file_ops char_dev_fops = {
    .open = char_dev_open,
};

static struct block_dev* block_devices;

int block_dev_register(struct block_dev* block_dev) {
    ASSERT(!block_dev->next);
    struct inode* inode = block_dev->inode;
    if (!S_ISBLK(inode->mode))
        return -ENODEV;
    for (struct block_dev* it = block_devices; it; it = it->next) {
        if (it->inode->rdev == inode->rdev)
            return -EEXIST;
        if (!strcmp(it->name, block_dev->name))
            return -EEXIST;
    }
    block_dev->next = block_devices;
    block_devices = block_dev;
    kprintf("block_dev: registered %s %u,%u\n", block_dev->name,
            major(inode->rdev), minor(inode->rdev));
    return 0;
}

struct block_dev* block_dev_get(dev_t rdev) {
    for (struct block_dev* it = block_devices; it; it = it->next) {
        if (it->inode->rdev == rdev)
            return it;
    }
    return NULL;
}

dev_t block_dev_generate_unnamed_device_number(void) {
    static int next_id = 1;
    int id = next_id++;
    return makedev(UNNAMED_MAJOR, id);
}
