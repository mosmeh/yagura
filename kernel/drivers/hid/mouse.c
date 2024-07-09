#include "hid.h"
#include <kernel/api/hid.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/scheduler.h>

static void write_mouse(uint8_t data) {
    ps2_write(PS2_COMMAND, 0xd4);
    ps2_write(PS2_DATA, data);
    ASSERT(ps2_read(PS2_DATA) == PS2_ACK);
}

#define QUEUE_SIZE 128

static uint8_t buf[3];
static size_t state = 0;

static mouse_event queue[QUEUE_SIZE];
static size_t queue_read_idx = 0;
static size_t queue_write_idx = 0;

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

        queue[queue_write_idx] = (mouse_event){dx, -dy, buf[0] & 7};
        queue_write_idx = (queue_write_idx + 1) % QUEUE_SIZE;

        state = 0;
        return;
    }
    }
    UNREACHABLE();
}

static bool can_read(void) {
    bool int_flag = push_cli();
    bool ret = queue_read_idx != queue_write_idx;
    pop_cli(int_flag);
    return ret;
}

static bool unblock_read(struct file* file) {
    (void)file;
    return can_read();
}

static ssize_t ps2_mouse_device_read(struct file* file, void* buffer,
                                     size_t count) {
    for (;;) {
        int rc = file_block(file, unblock_read, 0);
        if (IS_ERR(rc))
            return rc;

        bool int_flag = push_cli();
        if (queue_read_idx == queue_write_idx) {
            pop_cli(int_flag);
            continue;
        }

        size_t nread = 0;
        mouse_event* out = (mouse_event*)buffer;
        while (count > 0) {
            if (queue_read_idx == queue_write_idx ||
                count < sizeof(mouse_event))
                break;
            *out++ = queue[queue_read_idx];
            nread += sizeof(mouse_event);
            count -= sizeof(mouse_event);
            queue_read_idx = (queue_read_idx + 1) % QUEUE_SIZE;
        }
        pop_cli(int_flag);
        return nread;
    }
}

static short ps2_mouse_device_poll(struct file* file, short events) {
    (void)file;
    short revents = 0;
    if ((events & POLLIN) && can_read())
        revents |= POLLIN;
    if (events & POLLOUT)
        revents |= POLLOUT;
    return revents;
}

static struct inode* ps2_mouse_device_get(void) {
    static file_ops fops = {.read = ps2_mouse_device_read,
                            .poll = ps2_mouse_device_poll};
    static struct inode inode = {
        .fops = &fops, .mode = S_IFCHR, .rdev = makedev(10, 1), .ref_count = 1};
    return &inode;
}

void ps2_mouse_init(void) {
    ps2_write(PS2_COMMAND, PS2_ENABLE_PORT2);
    write_mouse(PS2_MOUSE_SET_DEFAULTS);
    write_mouse(PS2_MOUSE_ENABLE_PACKET_STREAMING);
    idt_set_interrupt_handler(IRQ(12), irq_handler);

    ASSERT_OK(vfs_register_device("psaux", ps2_mouse_device_get()));
}
