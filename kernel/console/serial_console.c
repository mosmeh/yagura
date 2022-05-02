#include "console.h"
#include <kernel/api/signum.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/interrupts.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/ring_buf.h>
#include <kernel/scheduler.h>
#include <kernel/serial.h>

static ring_buf input_bufs[4];
static pid_t pgid;

void serial_console_init(void) {
    for (size_t i = 0; i < 4; ++i)
        ASSERT_OK(ring_buf_init(input_bufs + i));
}

static ring_buf* get_input_buf_for_port(uint16_t port) {
    uint8_t com_number = serial_port_to_com_number(port);
    if (com_number)
        return input_bufs + (com_number - 1);
    return NULL;
}

void serial_console_on_char(uint16_t port, char ch) {
    ring_buf* buf = get_input_buf_for_port(port);
    if (!buf)
        return;

    tty_maybe_send_signal(pgid, ch);

    bool int_flag = push_cli();
    ring_buf_write_evicting_oldest(buf, &ch, 1);
    pop_cli(int_flag);
}

typedef struct serial_console_device {
    struct file base_file;
    uint16_t port;
} serial_console_device;

static bool read_should_unblock(const ring_buf* buf) {
    bool int_flag = push_cli();
    bool should_unblock = !ring_buf_is_empty(buf);
    pop_cli(int_flag);
    return should_unblock;
}

static ssize_t serial_console_device_read(file_description* desc, void* buffer,
                                          size_t count) {
    serial_console_device* dev = (serial_console_device*)desc->file;
    ring_buf* buf = get_input_buf_for_port(dev->port);
    int rc = scheduler_block(read_should_unblock, buf);
    if (IS_ERR(rc))
        return rc;

    bool int_flag = push_cli();
    ssize_t nread = ring_buf_read(buf, buffer, count);
    pop_cli(int_flag);

    return nread;
}

static ssize_t serial_console_device_write(file_description* desc,
                                           const void* buffer, size_t count) {
    serial_console_device* dev = (serial_console_device*)desc->file;
    return serial_write(dev->port, (const char*)buffer, count);
}

static int serial_console_device_ioctl(file_description* desc, int request,
                                       void* argp) {
    (void)desc;
    switch (request) {
    case TIOCGPGRP:
        *(pid_t*)argp = pgid;
        return 0;
    case TIOCSPGRP: {
        pid_t new_pgid = *(pid_t*)argp;
        if (new_pgid < 0)
            return -EINVAL;
        pgid = new_pgid;
        return 0;
    }
    case TIOCGWINSZ:
        return -ENOTSUP;
    }
    return -EINVAL;
}

struct file* serial_console_device_create(uint16_t port) {
    if (!serial_is_valid_port(port))
        return NULL;

    serial_console_device* dev = kmalloc(sizeof(serial_console_device));
    if (!dev)
        return ERR_PTR(-ENOMEM);
    *dev = (serial_console_device){0};

    dev->port = port;

    struct file* file = (struct file*)dev;
    file->name = kstrdup("serial_console_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFCHR;
    file->read = serial_console_device_read;
    file->write = serial_console_device_write;
    file->ioctl = serial_console_device_ioctl;

    file->device_id = makedev(4, 63 + (dev_t)serial_port_to_com_number(port));

    return file;
}