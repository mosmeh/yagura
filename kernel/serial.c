#include "serial.h"
#include "asm_wrapper.h"
#include "kmalloc.h"
#include "string.h"
#include "system.h"
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
    serial_enable_port(SERIAL_COM1);
    serial_enable_port(SERIAL_COM2);
    serial_enable_port(SERIAL_COM3);
    serial_enable_port(SERIAL_COM4);
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

static uint32_t serial_device_read(fs_node* node, off_t offset, size_t size,
                                   void* buffer) {
    (void)node;
    (void)offset;
    (void)size;
    (void)buffer;
    KUNIMPLEMENTED();
    return 0;
}

static uint32_t serial_device_write(fs_node* node, off_t offset, size_t size,
                                    const void* buffer) {
    (void)offset;
    char* chars = (char*)buffer;
    for (size_t i = 0; i < size; ++i)
        serial_write(node->inode, chars[i]);
    return size;
}

fs_node* serial_device_create(uint16_t port) {
    fs_node* node = kmalloc(sizeof(fs_node));
    memset(node, 0, sizeof(fs_node));
    node->name = kstrdup("serial_device");
    node->flags = FS_CHARDEVICE;
    node->inode = port;
    node->read = serial_device_read;
    node->write = serial_device_write;
    return node;
}
