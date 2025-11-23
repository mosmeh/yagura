#include "private.h"
#include <kernel/api/fcntl.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/system.h>

static struct file* active_console;

static ssize_t system_console_device_pread(struct file* file, void* buffer,
                                           size_t count, uint64_t offset) {
    (void)file;
    return file_pread(active_console, buffer, count, offset);
}

static ssize_t system_console_device_pwrite(struct file* file,
                                            const void* buffer, size_t count,
                                            uint64_t offset) {
    (void)file;
    return file_pwrite(active_console, buffer, count, offset);
}

static int system_console_device_ioctl(struct file* file, int request,
                                       void* user_argp) {
    (void)file;
    return file_ioctl(active_console, request, user_argp);
}

static short system_console_device_poll(struct file* file, short events) {
    (void)file;
    return file_poll(active_console, events);
}

static struct inode* system_console_device_get(void) {
    static const struct file_ops fops = {
        .pread = system_console_device_pread,
        .pwrite = system_console_device_pwrite,
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
    if (!S_ISCHR(device->mode)) {
        kprintf("system_console: device %s is not a character device\n",
                console);
        return;
    }

    active_console = inode_open(device, O_RDWR);
    if (!active_console) {
        kprintf("system_console: failed to open device %s\n", console);
        return;
    }

    kprintf("system_console: using %s\n", console);

    ASSERT_OK(vfs_register_device("console", system_console_device_get()));
}
