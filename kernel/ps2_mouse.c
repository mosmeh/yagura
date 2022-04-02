#include "api/err.h"
#include "api/hid.h"
#include "api/stat.h"
#include "asm_wrapper.h"
#include "fs/fs.h"
#include "kernel/interrupts.h"
#include "kmalloc.h"
#include "lock.h"
#include "panic.h"
#include <common/string.h>

#define PS2_DATA 0x60
#define PS2_STATUS 0x64
#define PS2_COMMAND 0x64
#define PS2_DISABLE_PORT2 0xa7
#define PS2_ENABLE_PORT2 0xa8
#define PS2_DISABLE_PORT1 0xad
#define PS2_ENABLE_PORT1 0xae
#define PS2_MOUSE_ENABLE_PACKET_STREAMING 0xf4
#define PS2_MOUSE_SET_DEFAULTS 0xf6
#define PS2_ACK 0xfa

static uint8_t read(uint8_t port) {
    while (!(in8(PS2_STATUS) & 1))
        pause();
    return in8(port);
}

static void write(uint8_t port, uint8_t data) {
    while (in8(PS2_COMMAND) & 2)
        pause();
    out8(port, data);
}

static void write_mouse(uint8_t data) {
    write(PS2_COMMAND, 0xd4);
    write(PS2_DATA, data);
    ASSERT(read(PS2_DATA) == PS2_ACK);
}

static uint8_t buf[3];
static size_t state = 0;

#define QUEUE_SIZE 32
static mouse_packet queue[QUEUE_SIZE];
static size_t queue_head = 0;
static size_t queue_tail = 0;
static mutex queue_lock;

static void irq_handler(registers* reg) {
    (void)reg;

    uint8_t data = in8(PS2_DATA);
    buf[state] = data;
    switch (state) {
    case 0:
        ASSERT(data & 8);
        ++state;
        return;
    case 1:
        ++state;
        return;
    case 2: {
        int dx = buf[1];
        int dy = buf[2];
        if (dx && (buf[0] & 0x10))
            dx -= 0x100;
        if (dy && (buf[0] & 0x20))
            dy -= 0x100;
        if (buf[0] & 0xc0)
            dx = dy = 0;

        queue[queue_tail] = (mouse_packet){dx, dy, buf[0] & 7};
        queue_tail = (queue_tail + 1) % QUEUE_SIZE;

        state = 0;
        return;
    }
    }
    UNREACHABLE();
}

void ps2_mouse_init(void) {
    write(PS2_COMMAND, PS2_DISABLE_PORT1);
    write(PS2_COMMAND, PS2_DISABLE_PORT2);

    write(PS2_COMMAND, 0x20); // read config
    uint8_t config = read(PS2_DATA);
    write(PS2_COMMAND, 0x60);    // write config
    write(PS2_DATA, config | 2); // enable IRQ12

    write(PS2_COMMAND, PS2_ENABLE_PORT2);

    write_mouse(PS2_MOUSE_SET_DEFAULTS);
    write_mouse(PS2_MOUSE_ENABLE_PACKET_STREAMING);

    idt_register_interrupt_handler(IRQ(12), irq_handler);

    mutex_init(&queue_lock);
}

static ssize_t ps2_mouse_device_read(file_description* desc, void* buffer,
                                     size_t count) {
    (void)desc;

    size_t nread = 0;
    mouse_packet* out = (mouse_packet*)buffer;

    mutex_lock(&queue_lock);
    while (count > 0) {
        if (queue_head == queue_tail || count < sizeof(mouse_packet))
            break;
        *out++ = queue[queue_head];
        nread += sizeof(mouse_packet);
        count -= sizeof(mouse_packet);
        queue_head = (queue_head + 1) % QUEUE_SIZE;
    }
    mutex_unlock(&queue_lock);

    return nread;
}

struct file* ps2_mouse_device_create(void) {
    struct file* file = kmalloc(sizeof(struct file));
    if (!file)
        return ERR_PTR(-ENOMEM);

    memset(file, 0, sizeof(struct file));

    file->name = kstrdup("ps2_mouse_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFCHR;
    file->read = ps2_mouse_device_read;
    return file;
}
