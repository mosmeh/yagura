#include "api/err.h"
#include "api/stat.h"
#include "api/sysmacros.h"
#include "fs/fs.h"
#include "kmalloc.h"
#include "system.h"
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

struct file* null_device_create(void) {
    struct file* file = kmalloc(sizeof(struct file));
    if (!file)
        return ERR_PTR(-ENOMEM);
    *file = (struct file){0};

    file->name = kstrdup("null_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFCHR;
    file->read = read_nothing;
    file->write = write_to_bit_bucket;
    file->device_id = makedev(1, 3);
    return file;
}

struct file* zero_device_create(void) {
    struct file* file = kmalloc(sizeof(struct file));
    if (!file)
        return ERR_PTR(-ENOMEM);
    *file = (struct file){0};

    file->name = kstrdup("zero_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFCHR;
    file->read = read_zeros;
    file->write = write_to_bit_bucket;
    file->device_id = makedev(1, 5);
    return file;
}

struct file* full_device_create(void) {
    struct file* file = kmalloc(sizeof(struct file));
    if (!file)
        return ERR_PTR(-ENOMEM);
    *file = (struct file){0};

    file->name = kstrdup("full_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFCHR;
    file->read = read_zeros;
    file->write = write_to_full_disk;
    file->device_id = makedev(1, 7);
    return file;
}
