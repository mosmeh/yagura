#include <common/string.h>
#include <kernel/api/errno.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/device.h>
#include <kernel/fs/file.h>
#include <kernel/fs/vfs.h>
#include <kernel/kmsg.h>
#include <kernel/memory/phys.h>
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

    int rc = devtmpfs_mknod(char_dev->name, S_IFCHR, char_dev->dev);
    if (IS_ERR(rc))
        kprintf("char_dev: failed to create device node for %s in devtmpfs "
                "(error %d)\n",
                char_dev->name, rc);

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

static struct block_dev* block_dev_from_inode(struct inode* inode) {
    return CONTAINER_OF(inode, struct block_dev, vfs_inode);
}

static int bdev_read(struct inode* inode, struct page* page,
                     size_t page_index) {
    struct block_dev* block_dev = block_dev_from_inode(inode);
    ASSERT_PTR(block_dev->bops->read);

    ASSERT(PAGE_SHIFT >= block_dev->block_bits);
    size_t nblocks_per_page = 1UL << (PAGE_SHIFT - block_dev->block_bits);

    uint64_t block_index = (uint64_t)page_index * nblocks_per_page;
    ASSERT(block_index < block_dev->num_blocks);

    size_t nblocks_to_read =
        MIN(nblocks_per_page, block_dev->num_blocks - block_index);

    int rc = block_dev->bops->read(block_dev, page_to_phys(page), block_index,
                                   nblocks_to_read);
    if (IS_ERR(rc))
        return rc;

    if (nblocks_to_read < nblocks_per_page) {
        size_t offset = nblocks_to_read << block_dev->block_bits;
        page_fill(page, 0, offset, PAGE_SIZE - offset);
    }

    return 0;
}

static int bdev_write(struct inode* inode, struct page* page,
                      size_t page_index) {
    struct block_dev* block_dev = block_dev_from_inode(inode);
    if (!block_dev->bops->write)
        return -EPERM;

    ASSERT(PAGE_SHIFT >= block_dev->block_bits);
    size_t nblocks_per_page = 1UL << (PAGE_SHIFT - block_dev->block_bits);

    uint64_t block_index = (uint64_t)page_index * nblocks_per_page;
    ASSERT(block_index < block_dev->num_blocks);

    size_t nblocks_to_write =
        MIN(nblocks_per_page, block_dev->num_blocks - block_index);

    return block_dev->bops->write(block_dev, page_to_phys(page), block_index,
                                  nblocks_to_write);
}

static int bdev_sync(struct inode* inode) {
    struct block_dev* block_dev = block_dev_from_inode(inode);
    if (block_dev->bops->flush)
        return block_dev->bops->flush(block_dev);
    return 0;
}

static const struct inode_ops bdev_iops = {
    .read = bdev_read,
    .write = bdev_write,
    .sync = bdev_sync,
};
static const struct file_ops bdev_fops = {0};

static struct mount* bdev_mount;

int block_dev_register(struct block_dev* block_dev) {
    ASSERT(block_dev->dev > 0);
    ASSERT_PTR(block_dev->bops);
    ASSERT(block_dev->block_bits > 0);
    ASSERT(block_dev->num_blocks > 0);

    if (block_dev->block_bits < SECTOR_SHIFT ||
        PAGE_SHIFT < block_dev->block_bits)
        return -EINVAL;

    for (struct tree_node* node = tree_first(&bdev_mount->inodes); node;
         node = tree_next(node)) {
        struct block_dev* d =
            CONTAINER_OF(node, struct block_dev, vfs_inode.tree_node);
        if (d->dev == block_dev->dev)
            return -EEXIST;
        if (!strcmp(d->name, block_dev->name))
            return -EEXIST;
    }

    struct inode* inode = &block_dev->vfs_inode;
    inode->iops = &bdev_iops;
    inode->fops = &bdev_fops;

    inode->ino = block_dev->dev;
    inode->mode = S_IFBLK;

    inode->block_bits = block_dev->block_bits;
    inode->blocks =
        block_dev->num_blocks >> (PAGE_SHIFT - block_dev->block_bits);
    inode->size = block_dev->num_blocks << block_dev->block_bits;

    int rc = mount_commit_inode(bdev_mount, inode);
    if (IS_ERR(rc)) {
        block_dev_unref(block_dev);
        return rc;
    }

    kprintf("block_dev: registered %s %u,%u\n", block_dev->name,
            major(block_dev->dev), minor(block_dev->dev));

    rc = devtmpfs_mknod(block_dev->name, S_IFBLK, block_dev->dev);
    if (IS_ERR(rc))
        kprintf("block_dev: failed to create device node for %s in devtmpfs "
                "(error %d)\n",
                block_dev->name, rc);

    block_dev_unref(block_dev);
    return 0;
}

static int block_dev_open(struct file* file) {
    struct block_dev* block_dev = block_dev_get(file->inode->rdev);
    if (!block_dev)
        return -ENODEV;
    file->private_data = block_dev;
    file->filemap = block_dev->vfs_inode.filemap;
    return 0;
}

static void block_dev_close(struct file* file) {
    block_dev_unref(file->private_data);
    file->private_data = NULL;
}

static ssize_t block_dev_pwrite(struct file* file, const void* user_buffer,
                                size_t count, uint64_t offset) {
    if (count == 0)
        return 0;

    struct inode* inode = file->filemap->inode;
    struct block_dev* block_dev = block_dev_from_inode(inode);
    if (!block_dev->bops->write)
        return -EPERM;

    SCOPED_LOCK(inode, inode);

    if (offset >= inode->size)
        return -ENOSPC;

    count = MIN(count, inode->size - offset);
    return default_file_pwrite(file, user_buffer, count, offset);
}

const struct file_ops block_dev_fops = {
    .open = block_dev_open,
    .close = block_dev_close,
    .pwrite = block_dev_pwrite,
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

    bdev_mount = ASSERT_PTR(file_system_mount(&bdev_fs, "bdev"));
}
