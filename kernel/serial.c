#include "serial.h"
#include "api/err.h"
#include "api/stat.h"
#include "api/sysmacros.h"
#include "fs/fs.h"
#include "interrupts.h"
#include "kmalloc.h"
#include "lock.h"
#include "scheduler.h"
#include <string.h>

#define DATA_READY 0x1
#define TRANSMITTER_HOLDING_REGISTER_EMPTY 0x20

bool serial_enable_port(uint16_t port) {
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

static bool can_read(uint16_t port) { return in8(port + 5) & DATA_READY; }

static void write_char(uint16_t port, char c) {
    while (!(in8(port + 5) & TRANSMITTER_HOLDING_REGISTER_EMPTY))
        ;
    out8(port, c);
}

size_t serial_write(uint16_t port, const char* s, size_t count) {
    // this function is also called by kprintf, which can be used in critical
    // situations, so we protect it by disabling interrupts, not with mutex.
    bool int_flag = push_cli();

    for (size_t i = 0; i < count; ++i) {
        if (s[i] == '\n')
            write_char(port, '\r');
        write_char(port, s[i]);
    }

    pop_cli(int_flag);
    return count;
}

typedef struct serial_device {
    struct file base_file;
    uint16_t port;
    mutex lock;
} serial_device;

static bool read_should_unblock(const uint16_t* port) {
    return can_read(*port);
}

static ssize_t serial_device_read(file_description* desc, void* buffer,
                                  size_t count) {
    serial_device* dev = (serial_device*)desc->file;
    scheduler_block(read_should_unblock, &dev->port);

    mutex_lock(&dev->lock);

    if (!can_read(dev->port)) {
        mutex_unlock(&dev->lock);
        return 0;
    }

    char* chars = (char*)buffer;
    for (size_t i = 0; i < count; ++i)
        chars[i] = in8(dev->port);

    mutex_unlock(&dev->lock);
    return count;
}

static ssize_t serial_device_write(file_description* desc, const void* buffer,
                                   size_t count) {
    serial_device* dev = (serial_device*)desc->file;
    return serial_write(dev->port, (const char*)buffer, count);
}

struct file* serial_device_create(uint16_t port) {
    serial_device* dev = kmalloc(sizeof(serial_device));
    if (!dev)
        return ERR_PTR(-ENOMEM);
    *dev = (serial_device){0};

    dev->port = port;
    mutex_init(&dev->lock);

    struct file* file = (struct file*)dev;
    file->name = kstrdup("serial_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFCHR;
    file->read = serial_device_read;
    file->write = serial_device_write;
    file->device_id = makedev(4, port + 64 - SERIAL_COM1);
    return file;
}
