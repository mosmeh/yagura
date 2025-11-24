#include "private.h"
#include "screen/screen.h"
#include <common/stdio.h>
#include <common/string.h>
#include <kernel/api/hid.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/drivers/hid/hid.h>
#include <kernel/panic.h>

struct virtual_console {
    struct tty tty;
    struct vt* vt;
};

static struct virtual_console* consoles[6];
static struct virtual_console* active_console;

static void emit_str(const char* s) {
    tty_emit(&active_console->tty, s, strlen(s));
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
            active_console = consoles[event->keycode - KEYCODE_F1];
            vt_invalidate_all(active_console->vt);
            vt_flush(active_console->vt);
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
    tty_emit(&active_console->tty, &key, 1);
}

static void echo(struct tty* tty, const char* buf, size_t count) {
    struct virtual_console* console =
        CONTAINER_OF(tty, struct virtual_console, tty);
    vt_write(console->vt, buf, count);
    vt_flush(console->vt);
}

static struct virtual_console* virtual_console_create(uint8_t tty_num,
                                                      struct screen* screen) {
    struct virtual_console* console = kmalloc(sizeof(struct virtual_console));
    ASSERT(console);
    *console = (struct virtual_console){0};

    console->vt = vt_create(screen);
    ASSERT_OK(console->vt);

    struct tty* tty = &console->tty;

    char name[16];
    (void)sprintf(name, "tty%u", tty_num);
    ASSERT_OK(tty_init(tty, name, makedev(TTY_MAJOR, tty_num)));

    tty_set_echo(tty, echo);

    size_t num_columns;
    size_t num_rows;
    screen->get_size(screen, &num_columns, &num_rows);
    tty_set_size(tty, num_columns, num_rows);

    ASSERT_OK(char_dev_register(&tty->char_dev));

    return console;
}

void virtual_console_init(struct screen* screen) {
    for (size_t i = 0; i < ARRAY_SIZE(consoles); ++i) {
        uint8_t tty_num = i + 1;
        struct virtual_console* console =
            virtual_console_create(tty_num, screen);
        ASSERT_OK(console);
        consoles[i] = console;
    }
    active_console = consoles[0];

    ps2_set_key_event_handler(on_key_event);
}
