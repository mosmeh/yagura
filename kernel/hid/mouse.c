#include "hid.h"
#include <kernel/api/hid.h>
#include <kernel/api/stat.h>
#include <kernel/api/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts.h>
#include <kernel/kmalloc.h>
#include <kernel/panic.h>
#include <kernel/scheduler.h>
#include <string.h>

static void write_mouse(uint8_t data) {
    ps2_write(PS2_COMMAND, 0xd4);
    ps2_write(PS2_DATA, data);
    ASSERT(ps2_read(PS2_DATA) == PS2_ACK);
}

#define QUEUE_SIZE 128

static uint8_t buf[3];
static size_t state = 0;

static mouse_packet queue[QUEUE_SIZE];
static size_t queue_head = 0;
static size_t queue_tail = 0;

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
    write_mouse(PS2_MOUSE_SET_DEFAULTS);
    write_mouse(PS2_MOUSE_ENABLE_PACKET_STREAMING);

    idt_register_interrupt_handler(IRQ(12), irq_handler);
}

static bool read_should_unblock(void) {
    bool int_flag = push_cli();
    bool should_unblock = queue_head != queue_tail;
    pop_cli(int_flag);
    return should_unblock;
}

static ssize_t ps2_mouse_device_read(file_description* desc, void* buffer,
                                     size_t count) {
    (void)desc;

    size_t nread = 0;
    mouse_packet* out = (mouse_packet*)buffer;
    scheduler_block(read_should_unblock, NULL);

    bool int_flag = push_cli();

    while (count > 0) {
        if (queue_head == queue_tail || count < sizeof(mouse_packet))
            break;
        *out++ = queue[queue_head];
        nread += sizeof(mouse_packet);
        count -= sizeof(mouse_packet);
        queue_head = (queue_head + 1) % QUEUE_SIZE;
    }

    pop_cli(int_flag);

    return nread;
}

struct file* ps2_mouse_device_create(void) {
    struct file* file = kmalloc(sizeof(struct file));
    if (!file)
        return ERR_PTR(-ENOMEM);
    *file = (struct file){0};

    file->name = kstrdup("ps2_mouse_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFCHR;
    file->read = ps2_mouse_device_read;
    file->device_id = makedev(10, 0);
    return file;
}
