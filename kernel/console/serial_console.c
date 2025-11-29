#include "private.h"
#include <common/stdio.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/device.h>
#include <kernel/drivers/serial.h>
#include <kernel/fs/proc/private.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

#define MINOR_BASE 64

struct serial_console {
    struct tty tty;
    uint8_t index;
};

static struct serial_console* consoles[SERIAL_NUM_PORTS];

static void on_char(uint8_t index, char ch) {
    ASSERT(index < SERIAL_NUM_PORTS);
    struct serial_console* console = consoles[index];
    if (console)
        tty_emit(&console->tty, &ch, 1);
}

static void serial_console_echo(struct tty* tty, const char* buf,
                                size_t count) {
    struct serial_console* console =
        CONTAINER_OF(tty, struct serial_console, tty);
    serial_write(console->index, buf, count);
}

static struct serial_console* serial_console_create(uint8_t index) {
    struct serial_console* console = kmalloc(sizeof(struct serial_console));
    ASSERT(console);
    *console = (struct serial_console){
        .index = index,
    };

    static const struct tty_ops tty_ops = {
        .echo = serial_console_echo,
    };

    struct tty* tty = &console->tty;
    (void)snprintf(tty->name, sizeof(tty->name), "ttyS%u", index);
    tty->dev = makedev(TTY_MAJOR, MINOR_BASE + index);
    tty->ops = &tty_ops;

    ASSERT_OK(tty_register(tty));
    return console;
}

void serial_console_init(void) {
    for (uint8_t i = 0; i < SERIAL_NUM_PORTS; ++i) {
        if (serial_is_port_enabled(i)) {
            struct serial_console* console = serial_console_create(i);
            ASSERT_PTR(console);
            consoles[i] = console;
        }
    }
    serial_set_input_handler(on_char);
}
