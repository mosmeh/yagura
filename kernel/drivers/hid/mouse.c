#include "ps2.h"
#include <kernel/api/hid.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/device.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

static void write_mouse(uint8_t data) {
    ps2_write(PS2_COMMAND, 0xd4);
    ps2_write(PS2_DATA, data);
    ASSERT(ps2_read(PS2_DATA) == PS2_ACK);
}

#define QUEUE_SIZE 128

static uint8_t buf[3];
static size_t state = 0;

static struct mouse_event queue[QUEUE_SIZE];
static size_t queue_read_idx = 0;
static size_t queue_write_idx = 0;
static struct spinlock queue_lock;

static void irq_handler(struct registers* reg) {
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

        spinlock_lock(&queue_lock);
        queue[queue_write_idx] = (struct mouse_event){dx, -dy, buf[0] & 7};
        queue_write_idx = (queue_write_idx + 1) % QUEUE_SIZE;
        spinlock_unlock(&queue_lock);

        state = 0;
        return;
    }
    }
    UNREACHABLE();
}

static bool can_read(void) {
    spinlock_lock(&queue_lock);
    bool ret = queue_read_idx != queue_write_idx;
    spinlock_unlock(&queue_lock);
    return ret;
}

static bool unblock_read(struct file* file) {
    (void)file;
    return can_read();
}

static ssize_t ps2_mouse_device_pread(struct file* file, void* buffer,
                                      size_t count, uint64_t offset) {
    (void)offset;
    for (;;) {
        int rc = file_block(file, unblock_read, 0);
        if (IS_ERR(rc))
            return rc;

        spinlock_lock(&queue_lock);
        if (queue_read_idx == queue_write_idx) {
            spinlock_unlock(&queue_lock);
            continue;
        }

        size_t nread = 0;
        struct mouse_event* out = (struct mouse_event*)buffer;
        while (count > 0) {
            if (queue_read_idx == queue_write_idx ||
                count < sizeof(struct mouse_event))
                break;
            *out++ = queue[queue_read_idx];
            nread += sizeof(struct mouse_event);
            count -= sizeof(struct mouse_event);
            queue_read_idx = (queue_read_idx + 1) % QUEUE_SIZE;
        }
        spinlock_unlock(&queue_lock);
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

void ps2_mouse_init(void) {
    ps2_write(PS2_COMMAND, PS2_ENABLE_PORT2);
    write_mouse(PS2_MOUSE_SET_DEFAULTS);
    write_mouse(PS2_MOUSE_ENABLE_PACKET_STREAMING);
    idt_set_interrupt_handler(IRQ(12), irq_handler);

    static const struct file_ops fops = {
        .pread = ps2_mouse_device_pread,
        .poll = ps2_mouse_device_poll,
    };
    static struct char_dev char_dev = {
        .name = "psaux",
        .dev = makedev(MISC_MAJOR, 1),
        .fops = &fops,
    };
    ASSERT_OK(char_dev_register(&char_dev));
}
