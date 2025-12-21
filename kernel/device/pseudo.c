#include <common/string.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/device.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>
#include <kernel/system.h>

static ssize_t read_nothing(struct file* file, void* user_buffer, size_t count,
                            uint64_t offset) {
    (void)file;
    (void)user_buffer;
    (void)count;
    (void)offset;
    return 0;
}

static ssize_t read_zeros(struct file* file, void* user_buffer, size_t count,
                          uint64_t offset) {
    (void)file;
    (void)offset;
    if (clear_user(user_buffer, count))
        return -EFAULT;
    return count;
}

static ssize_t write_to_bit_bucket(struct file* file, const void* user_buffer,
                                   size_t count, uint64_t offset) {
    (void)file;
    (void)user_buffer;
    (void)offset;
    return count;
}

static ssize_t write_to_full_disk(struct file* file, const void* user_buffer,
                                  size_t count, uint64_t offset) {
    (void)file;
    (void)user_buffer;
    (void)offset;
    if (count > 0)
        return -ENOSPC;
    return 0;
}

static const struct file_ops null_fops = {
    .pread = read_nothing,
    .pwrite = write_to_bit_bucket,
};
static struct char_dev null = {
    .name = "null",
    .dev = makedev(MEM_MAJOR, 3),
    .fops = &null_fops,
};

static const struct file_ops zero_fops = {
    .pread = read_zeros,
    .pwrite = write_to_bit_bucket,
};
static struct char_dev zero = {
    .name = "zero",
    .dev = makedev(MEM_MAJOR, 5),
    .fops = &zero_fops,
};

static const struct file_ops full_fops = {
    .pread = read_zeros,
    .pwrite = write_to_full_disk,
};
static struct char_dev full = {
    .name = "full",
    .dev = makedev(MEM_MAJOR, 7),
    .fops = &full_fops,
};

static ssize_t random_pread(struct file* file, void* user_buffer, size_t count,
                            uint64_t offset) {
    (void)file;
    (void)offset;

    unsigned char buf[256];
    unsigned char* user_dest = user_buffer;
    size_t nread = 0;
    while (nread < count) {
        size_t to_read = MIN(count - nread, sizeof(buf));
        ssize_t n = random_get(buf, to_read);
        if (IS_ERR(n))
            return n;
        if (n == 0)
            break;
        if (copy_to_user(user_dest, buf, n))
            return -EFAULT;
        user_dest += n;
        nread += n;
    }
    return nread;
}

static const struct file_ops random_fops = {
    .pread = random_pread,
    .pwrite = write_to_bit_bucket,
};
static struct char_dev random = {
    .name = "random",
    .dev = makedev(MEM_MAJOR, 8),
    .fops = &random_fops,
};
static struct char_dev urandom = {
    .name = "urandom",
    .dev = makedev(MEM_MAJOR, 9),
    .fops = &random_fops,
};

static int kmsg_close(struct file* file) {
    kfree(file->private_data);
    return 0;
}

static ssize_t kmsg_pread(struct file* file, void* user_buffer, size_t count,
                          uint64_t offset) {
    struct kmsg {
        char data[KMSG_BUF_SIZE];
        size_t size;
    };

    struct kmsg* kmsg = file->private_data;
    if (!kmsg) {
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
    if (copy_to_user(user_buffer, kmsg->data + offset, count))
        return -EFAULT;
    return count;
}

static ssize_t kmsg_pwrite(struct file* file, const void* user_buffer,
                           size_t count, uint64_t offset) {
    (void)file;
    (void)offset;

    char buf[256];
    const unsigned char* user_src = user_buffer;
    size_t nwritten = 0;
    while (nwritten < count) {
        size_t to_write = MIN(count - nwritten, sizeof(buf));
        if (copy_from_user(buf, user_src, to_write))
            return -EFAULT;
        kmsg_write(buf, to_write);
        user_src += to_write;
        nwritten += to_write;
    }
    return nwritten;
}

static const struct file_ops kmsg_fops = {
    .close = kmsg_close,
    .pread = kmsg_pread,
    .pwrite = kmsg_pwrite,
};
static struct char_dev kmsg = {
    .name = "kmsg",
    .dev = makedev(MEM_MAJOR, 11),
    .fops = &kmsg_fops,
};

static struct char_dev* devices[] = {
    &null, &zero, &full, &random, &urandom, &kmsg,
};

void pseudo_devices_init(void) {
    for (size_t i = 0; i < ARRAY_SIZE(devices); ++i)
        ASSERT_OK(char_dev_register(devices[i]));
}
