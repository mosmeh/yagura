#include "private.h"
#include "screen/screen.h"
#include <common/stdio.h>
#include <common/string.h>
#include <kernel/api/linux/kd.h>
#include <kernel/api/linux/keyboard.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/linux/vt.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/drivers/hid/hid.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/sched.h>

#define NUM_CONSOLES 12

#define UNICODE_MASK 0xf000
#define U(x) ((x) ^ UNICODE_MASK)

struct virtual_console {
    struct tty tty;
    struct vt* vt;
    int mode;
};

static struct virtual_console* consoles[NUM_CONSOLES];
static _Atomic(struct virtual_console*) active_console;

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

static void on_raw(unsigned char scancode) {
    struct virtual_console* console = active_console;
    struct tty* tty = &console->tty;
    spinlock_lock(&tty->lock);
    if (console->mode == K_RAW) {
        char x = scancode;
        tty_emit(tty, &x, 1);
    }
    spinlock_unlock(&tty->lock);
}

static unsigned char modifiers;
extern unsigned short* key_maps[MAX_NR_KEYMAPS];
extern char* func_table[MAX_NR_FUNC];

static void xlate(unsigned char keycode, bool down) {
    const unsigned short* key_map = key_maps[modifiers];
    if (!key_map)
        return;

    unsigned short key_sym = key_map[keycode];
    unsigned char type = KTYP(key_sym);
    unsigned char value = KVAL(key_sym);

    if (type < KTYP(U(0))) {
        // FIXME: Handle Unicode characters
        return;
    }
    type -= KTYP(U(0));

    struct tty* tty = &active_console->tty;
    switch (type) {
    case KT_LATIN:
    case KT_LETTER:
        if (down) {
            char ch = value;
            tty_emit(tty, &ch, 1);
        }
        break;
    case KT_FN:
        if (down) {
            const char* s = func_table[value];
            if (s)
                tty_emit(tty, s, strlen(s));
        }
        break;
    case KT_SPEC:
        if (down) {
            switch (value) {
            case 1: { // Enter
                char ch = '\r';
                tty_emit(tty, &ch, 1);
                break;
            }
            }
        }
        break;
    case KT_CONS:
        if (down)
            activate_console(value);
        break;
    case KT_CUR: {
        static const char chars[] = "BDCA";
        if (down && value < strlen(chars)) {
            const char s[] = {0x1b, '[', chars[value]};
            tty_emit(tty, s, sizeof(s));
        }
        break;
    }
    case KT_SHIFT:
        if (value == KG_CAPSSHIFT)
            value = KG_SHIFT;
        if (value < 8) {
            if (down)
                modifiers |= 1 << value;
            else
                modifiers &= ~(1 << value);
        }
        break;
    }
}

static void on_key(unsigned char keycode, bool down) {
    struct virtual_console* console = active_console;
    struct tty* tty = &console->tty;
    spinlock_lock(&tty->lock);
    switch (console->mode) {
    case K_RAW:
        break;
    case K_XLATE:
        xlate(keycode, down);
        break;
    case K_MEDIUMRAW:
        if (keycode < 128) {
            char c = keycode | (!down << 7);
            tty_emit(tty, &c, 1);
        } else {
            const char s[3] = {
                !down << 7,
                (keycode >> 7) | 0x80,
                keycode | 0x80,
            };
            tty_emit(tty, s, sizeof(s));
        }
        break;
    default:
        UNREACHABLE();
    }
    spinlock_unlock(&tty->lock);
}

static const struct keyboard_events event_handlers = {
    .raw = on_raw,
    .key = on_key,
};

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
                                 unsigned cmd, unsigned long arg) {
    (void)file;
    struct virtual_console* console =
        CONTAINER_OF(tty, struct virtual_console, tty);

    switch (cmd) {
    case KDGKBTYPE: {
        char type = KB_101;
        if (copy_to_user((void*)arg, &type, sizeof(char)))
            return -EFAULT;
        break;
    }
    case KDGKBMODE: {
        spinlock_lock(&tty->lock);
        int mode = console->mode;
        spinlock_unlock(&tty->lock);
        if (copy_to_user((void*)arg, &mode, sizeof(int)))
            return -EFAULT;
        break;
    }
    case KDSKBMODE: {
        int mode = (int)arg;
        switch (mode) {
        case K_RAW:
        case K_XLATE:
        case K_MEDIUMRAW:
            break;
        default:
            return -EINVAL;
        }
        spinlock_lock(&tty->lock);
        console->mode = mode;
        spinlock_unlock(&tty->lock);
        break;
    }
    case VT_ACTIVATE: {
        if (arg == 0 || arg > NUM_CONSOLES)
            return -ENXIO;
        activate_console(arg - 1);
        break;
    }
    case VT_WAITACTIVE: {
        if (arg == 0 || arg > NUM_CONSOLES)
            return -ENXIO;
        struct virtual_console* console = consoles[arg - 1];
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
    *console = (struct virtual_console){
        .mode = K_XLATE,
    };

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

    keyboard_set_event_handlers(&event_handlers);
}
