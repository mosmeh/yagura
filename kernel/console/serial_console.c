#include "console_private.h"
#include <common/stdio.h>
#include <kernel/drivers/serial.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

typedef struct {
    struct tty tty;
    uint8_t index;
} serial_console_device;

static serial_console_device* devices[SERIAL_NUM_PORTS];

static void on_char(uint8_t index, char ch) {
    ASSERT(index < SERIAL_NUM_PORTS);
    serial_console_device* dev = devices[index];
    if (dev)
        tty_emit(&dev->tty, &ch, 1);
}

static void echo(const char* buf, size_t count, void* ctx) {
    serial_console_device* dev = (serial_console_device*)ctx;
    serial_write(dev->index, buf, count);
}

static serial_console_device* serial_console_device_create(uint8_t index) {
    serial_console_device* dev = kmalloc(sizeof(serial_console_device));
    if (!dev)
        return ERR_PTR(-ENOMEM);
    *dev = (serial_console_device){0};

    dev->index = index;

    uint8_t minor = 64 + index;
    int rc = tty_init(&dev->tty, minor);
    if (IS_ERR(rc)) {
        kfree(dev);
        return ERR_PTR(rc);
    }
    tty_set_echo(&dev->tty, echo, dev);

    return dev;
}

void serial_console_init(void) {
    for (uint8_t i = 0; i < SERIAL_NUM_PORTS; ++i) {
        if (serial_is_port_enabled(i)) {
            serial_console_device* dev = serial_console_device_create(i);
            ASSERT_OK(dev);

            char name[8];
            (void)snprintf(name, sizeof(name), "ttyS%u", i);

            struct inode* inode = &dev->tty.inode;
            inode_ref(inode);
            ASSERT_OK(vfs_register_device(name, inode));

            devices[i] = dev;
        }
    }
    serial_set_input_handler(on_char);
}
