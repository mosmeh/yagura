#include "private.h"
#include "screen/screen.h"
#include <common/stdio.h>
#include <common/string.h>
#include <kernel/api/hid.h>
#include <kernel/api/linux/kd.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/linux/vt.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/drivers/hid/hid.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/sched.h>

#define NUM_CONSOLES 6

struct virtual_console {
    struct tty tty;
    struct vt* vt;
};

static struct virtual_console* consoles[NUM_CONSOLES];
static _Atomic(struct virtual_console*) active_console;

static void emit_str(const char* s) {
    tty_emit(&active_console->tty, s, strlen(s));
}

static void activate_console(size_t index) {
    if (index >= NUM_CONSOLES)
        return;
    struct virtual_console* console = consoles[index];
    spinlock_lock(&console->tty.lock);
    vt_invalidate_all(console->vt);
    vt_flush(console->vt);
    spinlock_unlock(&console->tty.lock);
    active_console = console;
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
            activate_console(event->keycode - KEYCODE_F1);
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

static void virtual_console_echo(struct tty* tty, const char* buf,
                                 size_t count) {
    struct virtual_console* console =
        CONTAINER_OF(tty, struct virtual_console, tty);
    vt_write(console->vt, buf, count);
    vt_flush(console->vt);
}

static bool unblock_waitactive(void* ctx) {
    struct virtual_console* console = ctx;
    return active_console == console;
}

static int virtual_console_ioctl(struct tty* tty, struct file* file,
                                 int request, void* user_argp) {
    (void)tty;
    (void)file;

    switch (request) {
    case KDGKBTYPE: {
        char type = KB_101;
        if (copy_to_user(user_argp, &type, sizeof(char)))
            return -EFAULT;
        break;
    }
    case VT_ACTIVATE: {
        unsigned long n = (unsigned long)user_argp;
        if (n == 0 || n > NUM_CONSOLES)
            return -ENXIO;
        activate_console(n - 1);
        break;
    }
    case VT_WAITACTIVE: {
        unsigned long n = (unsigned long)user_argp;
        if (n == 0 || n > NUM_CONSOLES)
            return -ENXIO;
        struct virtual_console* console = consoles[n - 1];
        int rc = sched_block(unblock_waitactive, console, 0);
        if (IS_ERR(rc))
            return rc;
        break;
    }
    default:
        return -ENOTTY;
    }
    return 0;
}

static struct virtual_console* virtual_console_create(uint8_t tty_num,
                                                      struct screen* screen) {
    struct virtual_console* console = kmalloc(sizeof(struct virtual_console));
    ASSERT(console);
    *console = (struct virtual_console){0};

    console->vt = vt_create(screen);
    ASSERT_PTR(console->vt);

    static const struct tty_ops tty_ops = {
        .echo = virtual_console_echo,
        .ioctl = virtual_console_ioctl,
    };

    struct tty* tty = &console->tty;
    (void)snprintf(tty->name, sizeof(tty->name), "tty%u", tty_num);
    tty->dev = makedev(TTY_MAJOR, tty_num);
    tty->ops = &tty_ops;
    screen->get_size(screen, &tty->num_columns, &tty->num_rows);

    ASSERT_OK(tty_register(tty));
    return console;
}

void virtual_console_init(struct screen* screen) {
    for (size_t i = 0; i < NUM_CONSOLES; ++i) {
        uint8_t tty_num = i + 1;
        struct virtual_console* console =
            virtual_console_create(tty_num, screen);
        ASSERT_PTR(console);
        consoles[i] = console;
    }
    activate_console(0);

    ps2_set_key_event_handler(on_key_event);
}
