#include <kernel/api/err.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/system.h>
#include <kernel/vec.h>
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
    static file_ops fops = {
        .read = read_nothing,
        .write = write_to_bit_bucket,
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
    static file_ops fops = {
        .read = read_zeros,
        .write = write_to_bit_bucket,
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
    static file_ops fops = {
        .read = read_zeros,
        .write = write_to_full_disk,
    };
    static struct inode inode = {
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(1, 7),
        .ref_count = 1,
    };
    return &inode;
}

static ssize_t random_device_read(file_description* desc, void* buffer,
                                  size_t count) {
    (void)desc;
    return random_get(buffer, count);
}

static struct inode* random_device_get(void) {
    static file_ops fops = {
        .read = random_device_read,
        .write = write_to_bit_bucket,
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
    static file_ops fops = {
        .read = random_device_read,
        .write = write_to_bit_bucket,
    };
    static struct inode inode = {
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(1, 9),
        .ref_count = 1,
    };
    return &inode;
}

static int kmsg_device_close(file_description* desc) {
    kfree(desc->private_data);
    return 0;
}

static ssize_t kmsg_device_read(file_description* desc, void* buffer,
                                size_t count) {
    struct kmsg {
        char data[KMSG_BUF_SIZE];
        size_t size;
    };

    struct kmsg* kmsg = desc->private_data;
    if (!desc->private_data) {
        kmsg = kmalloc(sizeof(struct kmsg));
        if (!kmsg)
            return -ENOMEM;
        kmsg->size = kmsg_read(kmsg->data, KMSG_BUF_SIZE);
        desc->private_data = kmsg;
    }

    mutex_lock(&desc->offset_lock);
    if ((size_t)desc->offset >= kmsg->size) {
        count = 0;
        goto done;
    }
    if (desc->offset + count >= kmsg->size)
        count = kmsg->size - desc->offset;
    memcpy(buffer, kmsg->data + desc->offset, count);
    desc->offset += count;
done:
    mutex_unlock(&desc->offset_lock);

    return count;
}

static ssize_t kmsg_device_write(file_description* desc, const void* buffer,
                                 size_t count) {
    (void)desc;
    return kmsg_write(buffer, count);
}

static struct inode* kmsg_device_get(void) {
    static file_ops fops = {
        .close = kmsg_device_close,
        .read = kmsg_device_read,
        .write = kmsg_device_write,
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
