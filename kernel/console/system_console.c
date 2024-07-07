#include "console_private.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/system.h>

static file_description* active_console;

static ssize_t system_console_device_read(file_description* desc, void* buffer,
                                          size_t count) {
    (void)desc;
    return file_description_read(active_console, buffer, count);
}

static ssize_t system_console_device_write(file_description* desc,
                                           const void* buffer, size_t count) {
    (void)desc;
    return file_description_write(active_console, buffer, count);
}

static int system_console_device_ioctl(file_description* desc, int request,
                                       void* user_argp) {
    (void)desc;
    return file_description_ioctl(active_console, request, user_argp);
}

static short system_console_device_poll(file_description* desc, short events) {
    (void)desc;
    return file_description_poll(active_console, events);
}

static struct inode* system_console_device_get(void) {
    static file_ops fops = {
        .read = system_console_device_read,
        .write = system_console_device_write,
        .ioctl = system_console_device_ioctl,
        .poll = system_console_device_poll,
    };
    static struct inode inode = {
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(5, 1),
        .ref_count = 1,
    };
    return &inode;
}

void system_console_init(void) {
    const char* console = cmdline_lookup("console");
    if (!console)
        console = "tty1";

    struct inode* device = vfs_get_device_by_name(console);
    if (!device) {
        kprintf("system_console: device %s not found\n", console);
        return;
    }

    active_console = inode_open(device, O_RDWR, 0);
    if (!active_console) {
        kprintf("system_console: failed to open device %s\n", console);
        return;
    }

    kprintf("system_console: using %s\n", console);

    ASSERT_OK(vfs_register_device("console", system_console_device_get()));
}
