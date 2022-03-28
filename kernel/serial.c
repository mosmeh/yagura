#include "serial.h"
#include "asm_wrapper.h"
#include "kmalloc.h"
#include "panic.h"
#include "string.h"
#include <common/err.h>
#include <common/string.h>
#include <common/types.h>
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
    KASSERT(serial_enable_port(SERIAL_COM1));
    KASSERT(serial_enable_port(SERIAL_COM2));
    KASSERT(serial_enable_port(SERIAL_COM3));
    KASSERT(serial_enable_port(SERIAL_COM4));
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

static ssize_t serial_device_read(file_description* desc, void* buffer,
                                  size_t size) {
    (void)desc;
    (void)size;
    (void)buffer;
    KUNIMPLEMENTED();
    return 0;
}

static ssize_t serial_device_write(file_description* desc, const void* buffer,
                                   size_t size) {
    uint16_t port = desc->node->device;
    char* chars = (char*)buffer;
    for (size_t i = 0; i < size; ++i)
        serial_write(port, chars[i]);
    return size;
}

fs_node* serial_device_create(uint16_t port) {
    fs_node* node = kmalloc(sizeof(fs_node));
    if (!node)
        return ERR_PTR(-ENOMEM);

    memset(node, 0, sizeof(fs_node));

    node->name = kstrdup("serial_device");
    if (!node->name)
        return ERR_PTR(-ENOMEM);

    node->type = FS_CHAR_DEVICE;
    node->read = serial_device_read;
    node->write = serial_device_write;
    node->device = port;
    return node;
}
