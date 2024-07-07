#include "console_private.h"
#include <common/stdio.h>
#include <common/string.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/drivers/hid/hid.h>
#include <kernel/interrupts.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/ring_buf.h>
#include <kernel/safe_string.h>

#define NUM_VIRTUAL_CONSOLES 6

typedef struct virtual_console_device {
    struct inode inode;
    ring_buf input_buf;
    struct vt* vt;
    pid_t pgid;
    mutex lock;
} virtual_console_device;

static virtual_console_device* devices[NUM_VIRTUAL_CONSOLES];
static virtual_console_device* active_device;

static void emit(const char* s) {
    bool int_flag = push_cli();
    ring_buf_write_evicting_oldest(&active_device->input_buf, s, strlen(s));
    pop_cli(int_flag);
}

#define CTRL_ALT (KEY_MODIFIER_CTRL | KEY_MODIFIER_ALT)

static void on_key_event(const key_event* event) {
    if (!event->pressed)
        return;
    switch (event->keycode) {
    case KEYCODE_UP:
        emit("\x1b[A");
        return;
    case KEYCODE_DOWN:
        emit("\x1b[B");
        return;
    case KEYCODE_RIGHT:
        emit("\x1b[C");
        return;
    case KEYCODE_LEFT:
        emit("\x1b[D");
        return;
    case KEYCODE_HOME:
        emit("\x1b[H");
        return;
    case KEYCODE_END:
        emit("\x1b[F");
        return;
    case KEYCODE_DELETE:
        emit("\x1b[3~");
        return;
    case KEYCODE_F1:
    case KEYCODE_F2:
    case KEYCODE_F3:
    case KEYCODE_F4:
    case KEYCODE_F5:
    case KEYCODE_F6:
        if ((event->modifiers & CTRL_ALT) == CTRL_ALT) {
            active_device = devices[event->keycode - KEYCODE_F1];
            vt_invalidate_all(active_device->vt);
            vt_flush(active_device->vt);
            return;
        }
        break;
    }

    if (!event->key)
        return;
    char key = event->key;
    if (event->modifiers & KEY_MODIFIER_CTRL) {
        if ('a' <= key && key <= 'z')
            key -= '`';
        else if (key == '\\')
            key = 0x1c;
    }

    tty_maybe_send_signal(active_device->pgid, key);

    bool int_flag = push_cli();
    ring_buf_write_evicting_oldest(&active_device->input_buf, &key, 1);
    pop_cli(int_flag);
}

static bool can_read(virtual_console_device* dev) {
    bool int_flag = push_cli();
    bool ret = !ring_buf_is_empty(&dev->input_buf);
    pop_cli(int_flag);
    return ret;
}

static bool unblock_read(file_description* desc) {
    virtual_console_device* dev = (virtual_console_device*)desc->inode;
    return can_read(dev);
}

static ssize_t virtual_console_device_read(file_description* desc, void* buffer,
                                           size_t count) {
    virtual_console_device* dev = (virtual_console_device*)desc->inode;
    for (;;) {
        int rc = file_description_block(desc, unblock_read, 0);
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

static ssize_t virtual_console_device_write(file_description* desc,
                                            const void* buffer, size_t count) {
    virtual_console_device* dev = (virtual_console_device*)desc->inode;
    mutex_lock(&dev->lock);
    vt_write(dev->vt, buffer, count);
    vt_flush(dev->vt);
    mutex_unlock(&dev->lock);
    return count;
}

static struct screen* screen;

static int virtual_console_device_ioctl(file_description* desc, int request,
                                        void* user_argp) {
    virtual_console_device* dev = (virtual_console_device*)desc->inode;
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
    case TIOCGWINSZ: {
        size_t num_columns;
        size_t num_rows;
        screen->get_size(screen, &num_columns, &num_rows);
        struct winsize winsize = {
            .ws_col = num_columns,
            .ws_row = num_rows,
            .ws_xpixel = 0,
            .ws_ypixel = 0,
        };
        if (!copy_to_user(user_argp, &winsize, sizeof(struct winsize)))
            return -EFAULT;
        return 0;
    }
    }
    return -EINVAL;
}

static short virtual_console_device_poll(file_description* desc, short events) {
    virtual_console_device* dev = (virtual_console_device*)desc->inode;
    short revents = 0;
    if ((events & POLLIN) && can_read(dev))
        revents |= POLLIN;
    if (events & POLLOUT)
        revents |= POLLOUT;
    return revents;
}

static virtual_console_device* virtual_console_device_create(uint8_t tty) {
    virtual_console_device* dev = kmalloc(sizeof(virtual_console_device));
    if (!dev)
        return ERR_PTR(-ENOMEM);
    *dev = (virtual_console_device){0};

    int ret = ring_buf_init(&dev->input_buf, PAGE_SIZE);
    if (IS_ERR(ret))
        goto fail;

    dev->vt = vt_create(screen);
    if (!dev->vt) {
        ret = -ENOMEM;
        goto fail;
    }

    struct inode* inode = &dev->inode;
    static file_ops fops = {
        .read = virtual_console_device_read,
        .write = virtual_console_device_write,
        .ioctl = virtual_console_device_ioctl,
        .poll = virtual_console_device_poll,
    };
    *inode = (struct inode){
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(4, tty),
        .ref_count = 1,
    };
    return dev;

fail:
    kfree(dev);
    return ERR_PTR(ret);
}

void virtual_console_init(struct screen* s) {
    screen = s;

    for (uint8_t i = 0; i < NUM_VIRTUAL_CONSOLES; ++i) {
        uint8_t tty = i + 1;
        virtual_console_device* dev = virtual_console_device_create(tty);
        ASSERT_OK(dev);

        char name[16];
        (void)sprintf(name, "tty%u", tty);

        struct inode* inode = &dev->inode;
        inode_ref(inode);
        ASSERT_OK(vfs_register_device(name, inode));

        devices[i] = dev;
    }
    active_device = devices[0];

    ps2_set_key_event_handler(on_key_event);
}
