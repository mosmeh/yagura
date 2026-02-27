#include "private.h"
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/device.h>
#include <kernel/fs/file.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/system.h>

static dev_t backing_rdev;

static struct char_dev char_dev = {
    .name = "console",
    .dev = makedev(TTYAUX_MAJOR, 1),
    .fops = &tty_fops,
};

struct tty* system_console_get(void) {
    ASSERT(backing_rdev != char_dev.dev);
    return backing_rdev ? tty_get(backing_rdev) : NULL;
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
    backing_rdev = backing_dev->dev;
    kprintf("system_console: using %s\n", console);

    ASSERT_OK(char_dev_register(&char_dev));
}
