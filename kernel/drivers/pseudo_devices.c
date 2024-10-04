#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/containers/vec.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/system.h>

static ssize_t read_nothing(struct file* file, void* buffer, size_t count,
                            uint64_t offset) {
    (void)file;
    (void)buffer;
    (void)count;
    (void)offset;
    return 0;
}

static ssize_t read_zeros(struct file* file, void* buffer, size_t count,
                          uint64_t offset) {
    (void)file;
    (void)offset;
    memset(buffer, 0, count);
    return count;
}

static ssize_t write_to_bit_bucket(struct file* file, const void* buffer,
                                   size_t count, uint64_t offset) {
    (void)file;
    (void)buffer;
    (void)offset;
    return count;
}

static ssize_t write_to_full_disk(struct file* file, const void* buffer,
                                  size_t count, uint64_t offset) {
    (void)file;
    (void)buffer;
    (void)offset;
    if (count > 0)
        return -ENOSPC;
    return 0;
}

static struct inode* null_device_get(void) {
    static const struct file_ops fops = {
        .pread = read_nothing,
        .pwrite = write_to_bit_bucket,
    };
    static struct inode inode = {
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(1, 3),
        .ref_count = 1,
    };
    return &inode;
}

static struct inode* zero_device_get(void) {
    static const struct file_ops fops = {
        .pread = read_zeros,
        .pwrite = write_to_bit_bucket,
    };
    static struct inode inode = {
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(1, 5),
        .ref_count = 1,
    };
    return &inode;
}

static struct inode* full_device_get(void) {
    static const struct file_ops fops = {
        .pread = read_zeros,
        .pwrite = write_to_full_disk,
    };
    static struct inode inode = {
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(1, 7),
        .ref_count = 1,
    };
    return &inode;
}

static ssize_t random_device_pread(struct file* file, void* buffer,
                                   size_t count, uint64_t offset) {
    (void)file;
    (void)offset;
    return random_get(buffer, count);
}

static struct inode* random_device_get(void) {
    static const struct file_ops fops = {
        .pread = random_device_pread,
        .pwrite = write_to_bit_bucket,
    };
    static struct inode inode = {
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(1, 8),
        .ref_count = 1,
    };
    return &inode;
}

static struct inode* urandom_device_get(void) {
    static const struct file_ops fops = {
        .pread = random_device_pread,
        .pwrite = write_to_bit_bucket,
    };
    static struct inode inode = {
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(1, 9),
        .ref_count = 1,
    };
    return &inode;
}

static int kmsg_device_close(struct file* file) {
    kfree(file->private_data);
    return 0;
}

static ssize_t kmsg_device_pread(struct file* file, void* buffer, size_t count,
                                 uint64_t offset) {
    struct kmsg {
        char data[KMSG_BUF_SIZE];
        size_t size;
    };

    struct kmsg* kmsg = file->private_data;
    if (!file->private_data) {
        kmsg = kmalloc(sizeof(struct kmsg));
        if (!kmsg)
            return -ENOMEM;
        kmsg->size = kmsg_read(kmsg->data, KMSG_BUF_SIZE);
        file->private_data = kmsg;
    }

    if (offset >= kmsg->size)
        return 0;
    if (offset + count >= kmsg->size)
        count = kmsg->size - offset;
    memcpy(buffer, kmsg->data + offset, count);
    return count;
}

static ssize_t kmsg_device_pwrite(struct file* file, const void* buffer,
                                  size_t count, uint64_t offset) {
    (void)file;
    (void)offset;
    kmsg_write(buffer, count);
    return count;
}

static struct inode* kmsg_device_get(void) {
    static const struct file_ops fops = {
        .close = kmsg_device_close,
        .pread = kmsg_device_pread,
        .pwrite = kmsg_device_pwrite,
    };
    static struct inode inode = {
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(1, 11),
        .ref_count = 1,
    };
    return &inode;
}

void pseudo_devices_init(void) {
    ASSERT_OK(vfs_register_device("null", null_device_get()));
    ASSERT_OK(vfs_register_device("zero", zero_device_get()));
    ASSERT_OK(vfs_register_device("full", full_device_get()));
    ASSERT_OK(vfs_register_device("random", random_device_get()));
    ASSERT_OK(vfs_register_device("urandom", urandom_device_get()));
    ASSERT_OK(vfs_register_device("kmsg", kmsg_device_get()));
}
