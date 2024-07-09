#include "console_private.h"
#include <common/stdio.h>
#include <kernel/drivers/serial.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

typedef struct serial_console_device {
    struct tty tty;
    uint16_t port;
} serial_console_device;

static serial_console_device* devices[4];

void serial_console_on_char(uint16_t port, char ch) {
    uint8_t com_number = serial_port_to_com_number(port);
    if (!com_number)
        return;
    serial_console_device* dev = devices[com_number - 1];
    if (dev)
        tty_emit(&dev->tty, &ch, 1);
}

static void echo(const char* buf, size_t count, void* ctx) {
    serial_console_device* dev = (serial_console_device*)ctx;
    serial_write(dev->port, buf, count);
}

static serial_console_device* serial_console_device_create(uint16_t port) {
    if (!serial_is_valid_port(port))
        return ERR_PTR(-EINVAL);

    serial_console_device* dev = kmalloc(sizeof(serial_console_device));
    if (!dev)
        return ERR_PTR(-ENOMEM);
    *dev = (serial_console_device){0};

    dev->port = port;

    uint8_t minor = 63 + serial_port_to_com_number(port);
    int rc = tty_init(&dev->tty, minor);
    if (IS_ERR(rc)) {
        kfree(dev);
        return ERR_PTR(rc);
    }
    tty_set_echo(&dev->tty, echo, dev);

    return dev;
}

void serial_console_init(void) {
    static const uint16_t ports[] = {
        SERIAL_COM1,
        SERIAL_COM2,
        SERIAL_COM3,
        SERIAL_COM4,
    };
    for (size_t i = 0; i < ARRAY_SIZE(ports); ++i) {
        if (serial_is_port_enabled(ports[i])) {
            serial_console_device* dev = serial_console_device_create(ports[i]);
            ASSERT_OK(dev);

            char name[8];
            (void)snprintf(name, sizeof(name), "ttyS%u", i);

            struct inode* inode = &dev->tty.inode;
            inode_ref(inode);
            ASSERT_OK(vfs_register_device(name, inode));

            devices[i] = dev;
        }
    }
}
