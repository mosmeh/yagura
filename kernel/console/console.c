#include "console.h"
#include "kernel/panic.h"
#include "kernel/serial.h"
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stat.h>
#include <kernel/api/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/kmalloc.h>
#include <kernel/scheduler.h>
#include <string.h>

static file_description* tty = NULL;
static file_description* ttyS0 = NULL;

void console_init(void) {
    file_description* desc = vfs_open("/dev/ttyS0", O_RDWR, 0);
    if (IS_OK(desc))
        ttyS0 = desc;
    else
        ASSERT(PTR_ERR(desc) == -ENOENT);

    desc = vfs_open("/dev/tty", O_RDWR, 0);
    if (IS_OK(desc))
        tty = desc;
    else
        ASSERT(PTR_ERR(desc) == -ENOENT);
}

static ssize_t write_all(file_description* desc, const char* s, size_t count) {
    size_t total_nwritten = 0;
    while (total_nwritten < count) {
        ssize_t nwritten = fs_write(desc, s, count);
        if (IS_ERR(nwritten))
            return nwritten;
        s += nwritten;
        total_nwritten += nwritten;
    }
    return count;
}

static ssize_t console_device_read(file_description* desc, void* buffer,
                                   size_t count) {
    (void)desc;
    if (tty)
        return fs_read(tty, buffer, count);
    if (ttyS0)
        return fs_read(ttyS0, buffer, count);
    return 0;
}

static ssize_t console_device_write(file_description* desc, const void* buffer,
                                    size_t count) {
    (void)desc;
    if (ttyS0) {
        ssize_t nwritten = write_all(ttyS0, buffer, count);
        if (IS_ERR(nwritten))
            return nwritten;
    }
    if (tty) {
        ssize_t nwritten = write_all(tty, buffer, count);
        if (IS_ERR(nwritten))
            return nwritten;
    }
    return count;
}

struct file* console_device_create(void) {
    struct file* file = kmalloc(sizeof(struct file));
    if (!file)
        return ERR_PTR(-ENOMEM);
    *file = (struct file){0};
    file->name = kstrdup("console_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);
    file->mode = S_IFCHR;
    file->read = console_device_read;
    file->write = console_device_write;
    file->device_id = makedev(5, 1);
    return file;
}
