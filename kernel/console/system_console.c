#include "private.h"
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/device.h>
#include <kernel/fs/file.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/system.h>

static struct tty* backing_tty;

static int system_console_open(struct file* file) {
    ASSERT(backing_tty);
    file->private_data = backing_tty;
    file->fops = &tty_fops;
    return 0;
}

void system_console_init(void) {
    const char* console = cmdline_lookup("console");
    if (!console)
        console = "tty0";

    struct char_dev* backing_dev = char_dev_find_by_name(console);
    if (!backing_dev) {
        kprintf("system_console: device %s not found\n", console);
        return;
    }
    switch (major(backing_dev->dev)) {
    case TTY_MAJOR:
    case TTYAUX_MAJOR:
        break;
    default:
        kprintf("system_console: device %s is not a tty\n", console);
        return;
    }

    backing_tty = CONTAINER_OF(backing_dev, struct tty, char_dev);
    kprintf("system_console: using %s\n", console);

    static const struct file_ops fops = {
        .open = system_console_open,
    };
    static struct char_dev char_dev = {
        .name = "console",
        .dev = makedev(TTYAUX_MAJOR, 1),
        .fops = &fops,
    };
    ASSERT_OK(char_dev_register(&char_dev));
}
