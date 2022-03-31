#include "serial.h"
#include "api/err.h"
#include "api/stat.h"
#include "api/types.h"
#include "asm_wrapper.h"
#include "kmalloc.h"
#include "string.h"
#include <common/panic.h>
#include <common/string.h>
#include <kernel/fs/fs.h>
#include <stdbool.h>

static bool serial_enable_port(uint16_t port) {
    out8(port + 1, 0x00);
    out8(port + 3, 0x80);
    out8(port + 0, 0x03);
    out8(port + 1, 0x00);
    out8(port + 3, 0x03);
    out8(port + 2, 0xc7);
    out8(port + 4, 0x0b);
    out8(port + 4, 0x1e);
    out8(port + 0, 0xae);

    if (in8(port + 0) != 0xae)
        return false;

    out8(port + 4, 0x0f);
    return true;
}

void serial_init(void) {
    ASSERT(serial_enable_port(SERIAL_COM1));
    ASSERT(serial_enable_port(SERIAL_COM2));
    ASSERT(serial_enable_port(SERIAL_COM3));
    ASSERT(serial_enable_port(SERIAL_COM4));
}

static bool is_transmit_empty(uint16_t port) { return in8(port + 5) & 0x20; }

static void write_char(uint16_t port, char c) {
    while (!is_transmit_empty(port))
        ;

    out8(port, c);
}

void serial_write(uint16_t port, char c) {
    if (c == '\n')
        write_char(port, '\r');
    write_char(port, c);
}

typedef struct serial_device {
    struct file base_file;
    uint16_t port;
} serial_device;

static ssize_t serial_device_write(file_description* desc, const void* buffer,
                                   size_t count) {
    serial_device* dev = (serial_device*)desc->file;
    char* chars = (char*)buffer;
    for (size_t i = 0; i < count; ++i)
        serial_write(dev->port, chars[i]);
    return count;
}

struct file* serial_device_create(uint16_t port) {
    serial_device* dev = kmalloc(sizeof(serial_device));
    if (!dev)
        return ERR_PTR(-ENOMEM);

    memset(dev, 0, sizeof(serial_device));

    dev->port = port;

    struct file* file = (struct file*)dev;
    file->name = kstrdup("serial_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFCHR;
    file->write = serial_device_write;
    return file;
}
