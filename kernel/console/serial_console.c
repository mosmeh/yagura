#include "console_private.h"
#include <common/stdio.h>
#include <kernel/api/signum.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/drivers/serial.h>
#include <kernel/interrupts.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/ring_buf.h>
#include <kernel/safe_string.h>
#include <kernel/scheduler.h>

typedef struct serial_console_device {
    struct inode inode;
    uint16_t port;
    ring_buf input_buf;
    pid_t pgid;
} serial_console_device;

static serial_console_device* devices[4];

static serial_console_device* get_device_for_port(uint16_t port) {
    uint8_t com_number = serial_port_to_com_number(port);
    if (com_number)
        return devices[com_number - 1];
    return NULL;
}

void serial_console_on_char(uint16_t port, char ch) {
    serial_console_device* dev = get_device_for_port(port);
    if (!dev)
        return;

    tty_maybe_send_signal(dev->pgid, ch);

    bool int_flag = push_cli();
    ring_buf_write_evicting_oldest(&dev->input_buf, &ch, 1);
    pop_cli(int_flag);
}

static bool can_read(file_description* desc) {
    serial_console_device* dev = (serial_console_device*)desc->inode;
    bool int_flag = push_cli();
    bool ret = !ring_buf_is_empty(&dev->input_buf);
    pop_cli(int_flag);
    return ret;
}

static ssize_t serial_console_device_read(file_description* desc, void* buffer,
                                          size_t count) {
    serial_console_device* dev = (serial_console_device*)desc->inode;

    for (;;) {
        int rc = file_description_block(desc, can_read);
        if (IS_ERR(rc))
            return rc;

        bool int_flag = push_cli();
        if (ring_buf_is_empty(&dev->input_buf)) {
            pop_cli(int_flag);
            continue;
        }
        ssize_t nread = ring_buf_read(&dev->input_buf, buffer, count);
        pop_cli(int_flag);
        return nread;
    }
}

static ssize_t serial_console_device_write(file_description* desc,
                                           const void* buffer, size_t count) {
    serial_console_device* dev = (serial_console_device*)desc->inode;
    return serial_write(dev->port, (const char*)buffer, count);
}

static int serial_console_device_ioctl(file_description* desc, int request,
                                       void* user_argp) {
    (void)desc;
    serial_console_device* dev = (serial_console_device*)desc->inode;
    switch (request) {
    case TIOCGPGRP:
        if (!copy_to_user(user_argp, &dev->pgid, sizeof(pid_t)))
            return -EFAULT;
        return 0;
    case TIOCSPGRP: {
        pid_t new_pgid;
        if (!copy_from_user(&new_pgid, user_argp, sizeof(pid_t)))
            return -EFAULT;
        if (new_pgid < 0)
            return -EINVAL;
        dev->pgid = new_pgid;
        return 0;
    }
    case TIOCGWINSZ:
        return -ENOTSUP;
    }
    return -EINVAL;
}

static short serial_console_device_poll(file_description* desc, short events) {
    short revents = 0;
    if ((events & POLLIN) && can_read(desc))
        revents |= POLLIN;
    if (events & POLLOUT)
        revents |= POLLOUT;
    return revents;
}

static serial_console_device* serial_console_device_create(uint16_t port) {
    if (!serial_is_valid_port(port))
        return NULL;

    serial_console_device* dev = kmalloc(sizeof(serial_console_device));
    if (!dev)
        return ERR_PTR(-ENOMEM);
    *dev = (serial_console_device){0};

    dev->port = port;
    int rc = ring_buf_init(&dev->input_buf, PAGE_SIZE);
    if (IS_ERR(rc)) {
        kfree(dev);
        return ERR_PTR(rc);
    }

    struct inode* inode = (struct inode*)dev;
    static file_ops fops = {
        .read = serial_console_device_read,
        .write = serial_console_device_write,
        .ioctl = serial_console_device_ioctl,
        .poll = serial_console_device_poll,
    };
    inode->fops = &fops;
    inode->mode = S_IFCHR;
    inode->rdev = makedev(4, 63 + (dev_t)serial_port_to_com_number(port));
    inode->ref_count = 1;

    return dev;
}

void serial_console_init(void) {
    const uint16_t ports[] = {
        SERIAL_COM1,
        SERIAL_COM2,
        SERIAL_COM3,
        SERIAL_COM4,
    };
    for (size_t i = 0; i < ARRAY_SIZE(ports); ++i) {
        if (serial_is_port_enabled(ports[i])) {
            serial_console_device* device =
                serial_console_device_create(ports[i]);
            ASSERT_OK(device);
            devices[i] = device;

            char name[8];
            (void)snprintf(name, sizeof(name), "ttyS%u", i);
            ASSERT_OK(vfs_register_device(name, &device->inode));
        }
    }
}
