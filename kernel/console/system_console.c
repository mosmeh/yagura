#include "console.h"
#include "kernel/panic.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/memory/memory.h>

static file_description* active_console = NULL;

void system_console_init(void) {
    active_console = vfs_open("/dev/tty", O_RDWR, 0);
    if (IS_OK(active_console))
        return;

    active_console = vfs_open("/dev/ttyS0", O_RDWR, 0);
    if (IS_OK(active_console))
        return;

    UNIMPLEMENTED();
}

static ssize_t system_console_device_read(file_description* desc, void* buffer,
                                          size_t count) {
    (void)desc;
    return fs_read(active_console, buffer, count);
}

static ssize_t system_console_device_write(file_description* desc,
                                           const void* buffer, size_t count) {
    (void)desc;
    return fs_write(active_console, buffer, count);
}

static int system_console_device_ioctl(file_description* desc, int request,
                                       void* argp) {
    (void)desc;
    return fs_ioctl(active_console, request, argp);
}

struct file* system_console_device_create(void) {
    struct file* file = kmalloc(sizeof(struct file));
    if (!file)
        return ERR_PTR(-ENOMEM);
    *file = (struct file){0};

    file->name = kstrdup("system_console_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    static file_ops fops = {
        .read = system_console_device_read,
        .write = system_console_device_write,
        .ioctl = system_console_device_ioctl,
    };
    file->fops = &fops;
    file->mode = S_IFCHR;
    file->device_id = makedev(5, 1);
    return file;
}
