#include "console_private.h"
#include "screen/screen.h"
#include <common/stdio.h>
#include <common/string.h>
#include <kernel/api/hid.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/drivers/hid/hid.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>

typedef struct {
    struct tty tty;
    struct vt* vt;
} virtual_console_device;

static virtual_console_device* devices[6];
static virtual_console_device* active_device;

static void emit_str(const char* s) {
    tty_emit(&active_device->tty, s, strlen(s));
}

#define CTRL_ALT (KEY_MODIFIER_CTRL | KEY_MODIFIER_ALT)

static void on_key_event(const struct key_event* event) {
    if (!event->pressed)
        return;

    switch (event->keycode) {
    case KEYCODE_UP:
        emit_str("\x1b[A");
        return;
    case KEYCODE_DOWN:
        emit_str("\x1b[B");
        return;
    case KEYCODE_RIGHT:
        emit_str("\x1b[C");
        return;
    case KEYCODE_LEFT:
        emit_str("\x1b[D");
        return;
    case KEYCODE_HOME:
        emit_str("\x1b[H");
        return;
    case KEYCODE_END:
        emit_str("\x1b[F");
        return;
    case KEYCODE_DELETE:
        emit_str("\x1b[3~");
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
            key = CTRL(key);
        else if (key == '\\')
            key = 0x1c;
    }
    tty_emit(&active_device->tty, &key, 1);
}

static void echo(const char* buf, size_t count, void* ctx) {
    virtual_console_device* dev = (virtual_console_device*)ctx;
    vt_write(dev->vt, buf, count);
    vt_flush(dev->vt);
}

static virtual_console_device*
virtual_console_device_create(uint8_t tty, struct screen* screen) {
    virtual_console_device* dev = kmalloc(sizeof(virtual_console_device));
    if (!dev)
        return ERR_PTR(-ENOMEM);
    *dev = (virtual_console_device){0};

    int ret = 0;
    dev->vt = vt_create(screen);
    if (IS_ERR(dev->vt)) {
        ret = PTR_ERR(dev->vt);
        dev->vt = NULL;
        goto fail;
    }

    ret = tty_init(&dev->tty, tty);
    if (IS_ERR(ret))
        goto fail;

    tty_set_echo(&dev->tty, echo, dev);

    size_t num_columns;
    size_t num_rows;
    screen->get_size(screen, &num_columns, &num_rows);
    tty_set_size(&dev->tty, num_columns, num_rows);

    return dev;

fail:
    kfree(dev->vt);
    kfree(dev);
    return ERR_PTR(ret);
}

void virtual_console_init(struct screen* screen) {
    for (size_t i = 0; i < ARRAY_SIZE(devices); ++i) {
        uint8_t tty = i + 1;
        virtual_console_device* dev =
            virtual_console_device_create(tty, screen);
        ASSERT_OK(dev);

        char name[8];
        (void)sprintf(name, "tty%u", tty);

        struct inode* inode = &dev->tty.inode;
        inode_ref(inode);
        ASSERT_OK(vfs_register_device(name, inode));

        devices[i] = dev;
    }
    active_device = devices[0];

    ps2_set_key_event_handler(on_key_event);
}
