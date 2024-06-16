#include <kernel/api/err.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/system.h>
#include <string.h>

static ssize_t read_nothing(file_description* desc, void* buffer,
                            size_t count) {
    (void)desc;
    (void)buffer;
    (void)count;
    return 0;
}

static ssize_t read_zeros(file_description* desc, void* buffer, size_t count) {
    (void)desc;
    memset(buffer, 0, count);
    return count;
}

static ssize_t read_random(file_description* desc, void* buffer, size_t count) {
    (void)desc;
    return random_get(buffer, count);
}

static ssize_t write_to_bit_bucket(file_description* desc, const void* buffer,
                                   size_t count) {
    (void)desc;
    (void)buffer;
    return count;
}

static ssize_t write_to_full_disk(file_description* desc, const void* buffer,
                                  size_t count) {
    (void)desc;
    (void)buffer;
    if (count > 0)
        return -ENOSPC;
    return 0;
}

static struct inode* null_device_get(void) {
    static file_ops fops = {.read = read_nothing, .write = write_to_bit_bucket};
    static struct inode inode = {.fops = &fops,
                                 .mode = S_IFCHR,
                                 .device_id = makedev(1, 3),
                                 .ref_count = 1};
    return &inode;
}

static struct inode* zero_device_get(void) {
    static file_ops fops = {.read = read_zeros, .write = write_to_bit_bucket};
    static struct inode inode = {.fops = &fops,
                                 .mode = S_IFCHR,
                                 .device_id = makedev(1, 5),
                                 .ref_count = 1};
    return &inode;
}

static struct inode* full_device_get(void) {
    static file_ops fops = {.read = read_zeros, .write = write_to_full_disk};
    static struct inode inode = {.fops = &fops,
                                 .mode = S_IFCHR,
                                 .device_id = makedev(1, 7),
                                 .ref_count = 1};
    return &inode;
}

static struct inode* random_device_get(void) {
    static file_ops fops = {.read = read_random, .write = write_to_bit_bucket};
    static struct inode inode = {.fops = &fops,
                                 .mode = S_IFCHR,
                                 .device_id = makedev(1, 8),
                                 .ref_count = 1};
    return &inode;
}

static struct inode* urandom_device_get(void) {
    static file_ops fops = {.read = read_random, .write = write_to_bit_bucket};
    static struct inode inode = {.fops = &fops,
                                 .mode = S_IFCHR,
                                 .device_id = makedev(1, 9),
                                 .ref_count = 1};
    return &inode;
}

void pseudo_device_init(void) {
    ASSERT_OK(vfs_register_device(null_device_get()));
    ASSERT_OK(vfs_register_device(zero_device_get()));
    ASSERT_OK(vfs_register_device(full_device_get()));
    ASSERT_OK(vfs_register_device(random_device_get()));
    ASSERT_OK(vfs_register_device(urandom_device_get()));
}
