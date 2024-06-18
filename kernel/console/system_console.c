#include <kernel/api/fcntl.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/kprintf.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

static struct inode* get_tty_device(void) {
    const dev_t candidates[] = {
        makedev(5, 0),  // /dev/tty
        makedev(4, 64), // /dev/ttyS0
        makedev(4, 65), // /dev/ttyS1
        makedev(4, 66), // /dev/ttyS2
        makedev(4, 67), // /dev/ttyS3
    };
    for (size_t i = 0; i < ARRAY_SIZE(candidates); ++i) {
        struct inode* device = vfs_get_device(candidates[i]);
        if (device) {
            kprintf("system_console: using device %u,%u\n",
                    major(candidates[i]), minor(candidates[i]));
            return device;
        }
    }
    return NULL;
}

static file_description* active_console = NULL;

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

static struct inode* system_console_device_get(void) {
    static file_ops fops = {
        .read = system_console_device_read,
        .write = system_console_device_write,
        .ioctl = system_console_device_ioctl,
    };
    static struct inode inode = {
        .fops = &fops, .mode = S_IFCHR, .rdev = makedev(5, 1), .ref_count = 1};
    return &inode;
}

void system_console_init(void) {
    struct inode* device = get_tty_device();
    ASSERT_OK(device);
    active_console = inode_open(device, O_RDWR, 0);
    ASSERT_OK(active_console);

    ASSERT_OK(vfs_register_device(system_console_device_get()));
}
