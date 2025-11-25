#include "device.h"
#include <common/string.h>
#include <kernel/api/errno.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>

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

void block_dev_lock(struct block_dev* block_dev) {
    mutex_lock(&block_dev->vfs_inode.lock);
}

void block_dev_unlock(struct block_dev* block_dev) {
    mutex_unlock(&block_dev->vfs_inode.lock);
}

static struct block_dev* block_dev_from_inode(struct inode* inode) {
    return CONTAINER_OF(inode, struct block_dev, vfs_inode);
}

static size_t get_block_size(const struct block_dev* block_dev) {
    return 1 << block_dev->block_bits;
}

static ssize_t bdev_pread(struct inode* inode, void* buffer, size_t count,
                          uint64_t offset) {
    struct block_dev* block_dev = block_dev_from_inode(inode);
    ASSERT(block_dev->bops->read);
    size_t block_size = get_block_size(block_dev);
    uint32_t rem;
    size_t index = divmodu64(offset, block_size, &rem);
    if (rem != 0)
        return -EINVAL;
    size_t nblocks = divmodu64(count, block_size, &rem);
    if (rem != 0)
        return -EINVAL;
    int rc = block_dev->bops->read(block_dev, buffer, index, nblocks);
    if (IS_ERR(rc))
        return rc;
    return count;
}

static ssize_t bdev_pwrite(struct inode* inode, const void* buffer,
                           size_t count, uint64_t offset) {
    struct block_dev* block_dev = block_dev_from_inode(inode);
    if (!block_dev->bops->write)
        return -EPERM;
    size_t block_size = get_block_size(block_dev);
    uint32_t rem;
    size_t index = divmodu64(offset, block_size, &rem);
    if (rem != 0)
        return -EINVAL;
    size_t nblocks = divmodu64(count, block_size, &rem);
    if (rem != 0)
        return -EINVAL;
    int rc = block_dev->bops->write(block_dev, buffer, index, nblocks);
    if (IS_ERR(rc))
        return rc;
    return count;
}

static int bdev_fsync(struct inode* inode) {
    struct block_dev* block_dev = block_dev_from_inode(inode);
    if (block_dev->bops->flush)
        return block_dev->bops->flush(block_dev);
    return 0;
}

static const struct inode_ops bdev_iops = {
    .pread = bdev_pread,
    .pwrite = bdev_pwrite,
    .fsync = bdev_fsync,
};
static const struct file_ops bdev_fops = {0};

static struct mount* bdev_mount;

int block_dev_register(struct block_dev* block_dev) {
    ASSERT(block_dev->dev > 0);
    ASSERT(block_dev->bops);
    ASSERT(block_dev->block_bits > 0);
    ASSERT(block_dev->num_blocks > 0);

    if (block_dev->block_bits < SECTOR_SHIFT ||
        PAGE_SHIFT < block_dev->block_bits)
        return -EINVAL;

    for (struct inode* inode = bdev_mount->inodes; inode; inode = inode->next) {
        struct block_dev* it = CONTAINER_OF(inode, struct block_dev, vfs_inode);
        if (it->dev == block_dev->dev)
            return -EEXIST;
        if (!strcmp(it->name, block_dev->name))
            return -EEXIST;
    }

    struct inode* inode = &block_dev->vfs_inode;
    inode->iops = &bdev_iops;
    inode->fops = &bdev_fops;

    inode->ino = block_dev->dev;
    inode->mode = S_IFBLK;

    inode->block_bits = block_dev->block_bits;

    inode->blocks = block_dev->num_blocks;
    if (block_dev->block_bits < PAGE_SHIFT)
        inode->blocks >>= (PAGE_SHIFT - block_dev->block_bits);

    inode->size = (uint64_t)block_dev->num_blocks << block_dev->block_bits;

    int rc = mount_commit_inode(bdev_mount, inode);
    if (IS_ERR(rc))
        return PTR_ERR(rc);

    kprintf("block_dev: registered %s %u,%u\n", block_dev->name,
            major(block_dev->dev), minor(block_dev->dev));
    return 0;
}

static int block_dev_open(struct file* file) {
    if (file->inode->mount == bdev_mount) {
        // Opening the block device inode itself
        return 0;
    }

    // Opening a block device file
    struct block_dev* block_dev = block_dev_get(file->inode->rdev);
    if (!block_dev)
        return -ENODEV;
    file->filemap = block_dev->vfs_inode.filemap;
    return 0;
}

const struct file_ops block_dev_fops = {
    .open = block_dev_open,
};

struct block_dev* block_dev_get(dev_t rdev) {
    struct inode* inode = mount_lookup_inode(bdev_mount, rdev);
    if (!inode)
        return NULL;
    struct block_dev* block_dev =
        CONTAINER_OF(inode, struct block_dev, vfs_inode);
    return block_dev;
}

void pseudo_devices_init(void);

void device_init(void) {
    pseudo_devices_init();

    static struct file_system bdev_fs = {
        .name = "bdev",
        .flags = FILE_SYSTEM_KERNEL_ONLY,
    };
    ASSERT_OK(file_system_register(&bdev_fs));

    bdev_mount = file_system_mount(&bdev_fs, "bdev");
    ASSERT_OK(bdev_mount);
}
