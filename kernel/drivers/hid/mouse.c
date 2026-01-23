#include <kernel/api/linux/major.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/device.h>
#include <kernel/drivers/hid/ps2.h>
#include <kernel/fs/file.h>
#include <kernel/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>

static void write_mouse(uint8_t data) {
    ps2_write(PS2_COMMAND, 0xd4);
    ps2_write(PS2_DATA, data);
    uint8_t response = ps2_read(PS2_DATA);
    if (response != PS2_ACK)
        kprintf("ps2_mouse: expected ACK, got %#x\n", response);
}

static unsigned char buf[3];
static size_t state = 0;

#define QUEUE_SIZE (sizeof(buf) * 16 + 1) // +1 to distinguish full vs empty

static unsigned char queue[QUEUE_SIZE];
static size_t read_index = 0;
static size_t write_index = 0;
static struct spinlock queue_lock;

static void irq_handler(struct registers* reg) {
    (void)reg;

    uint8_t data = in8(PS2_DATA);
    buf[state] = data;
    switch (state) {
    case 0:
        if (!(data & 8)) {
            kprintf("ps2_mouse: invalid packet %#x\n", data);
            return;
        }
        ++state;
        return;
    case 1:
        ++state;
        return;
    case 2: {
        SCOPED_LOCK(spinlock, &queue_lock);
        for (size_t i = 0; i < sizeof(buf); ++i) {
            queue[write_index] = buf[i];
            write_index = (write_index + 1) % QUEUE_SIZE;
            if (write_index == read_index)
                read_index = (read_index + 1) % QUEUE_SIZE;
        }
        state = 0;
        return;
    }
    }
    UNREACHABLE();
}

static bool can_read(void) {
    SCOPED_LOCK(spinlock, &queue_lock);
    return read_index != write_index;
}

static bool unblock_read(struct file* file) {
    (void)file;
    return can_read();
}

static ssize_t ps2_mouse_pread(struct file* file, void* user_buffer,
                               size_t count, uint64_t offset) {
    (void)offset;

    unsigned char* user_out = user_buffer;

    // Ensure no page faults occur while spinlock is held
    int rc = vm_populate(user_out, user_out + count, VM_WRITE);
    if (IS_ERR(rc))
        return rc;

    for (;;) {
        int rc = file_block(file, unblock_read, 0);
        if (IS_ERR(rc))
            return rc;

        SCOPED_LOCK(spinlock, &queue_lock);

        size_t nread = 0;
        while (nread < count) {
            if (read_index == write_index)
                break;
            if (copy_to_user(user_out, &queue[read_index],
                             sizeof(unsigned char)))
                return -EFAULT;
            ++nread;
            ++user_out;
            read_index = (read_index + 1) % QUEUE_SIZE;
        }

        if (nread > 0)
            return nread;
    }
}

static short ps2_mouse_poll(struct file* file, short events) {
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
    arch_interrupts_set_handler(IRQ(12), irq_handler);

    static const struct file_ops fops = {
        .pread = ps2_mouse_pread,
        .poll = ps2_mouse_poll,
    };
    static struct char_dev char_dev = {
        .name = "psaux",
        .dev = makedev(MISC_MAJOR, 1),
        .fops = &fops,
    };
    ASSERT_OK(char_dev_register(&char_dev));
}
