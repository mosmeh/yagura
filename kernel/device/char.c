#include <common/string.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/char.h>
#include <kernel/fs/file.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/vfs.h>
#include <kernel/kmsg.h>

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
