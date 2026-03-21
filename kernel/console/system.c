#include "private.h"
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/console/console.h>
#include <kernel/device/device.h>
#include <kernel/drivers/serial.h>
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

void system_console_echo(const char* buf, size_t count) {
    struct tty* tty = system_console_get();
    if (tty)
        tty_echo(tty, buf, count);
    else
        serial_write(0, buf, count);
}

void system_console_init(void) {
    const char* console = cmdline_lookup("console");
    if (!console)
        console = "tty0";

    struct char_dev* backing_dev = char_dev_find_by_name(console);
    if (backing_dev) {
        kprintf("system_console: switching to %s\n", console);
        backing_rdev = backing_dev->dev;

        kprint("system_console: replaying early logs\n");
        for (size_t offset = 0;;) {
            char buf[1024];
            size_t nread = kmsg_read(buf, sizeof(buf), offset);
            if (nread == 0)
                break;
            offset += nread;
            system_console_echo(buf, nread);
        }
    } else {
        kprintf("system_console: device %s not found\n", console);
    }

    ASSERT_OK(char_dev_register(&char_dev));
}
