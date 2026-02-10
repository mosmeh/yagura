#include "private.h"
#include <common/integer.h>
#include <common/stdio.h>
#include <common/string.h>
#include <kernel/api/linux/kd.h>
#include <kernel/api/linux/keyboard.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/linux/vt.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/console/screen/screen.h>
#include <kernel/drivers/hid/hid.h>
#include <kernel/fs/file.h>
#include <kernel/interrupts.h>
#include <kernel/panic.h>
#include <kernel/sched.h>

#define NUM_CONSOLES 12
#define NR_TYPES 15

#define UNICODE_MASK 0xf000
#define U(x) ((x) ^ UNICODE_MASK)

struct virtual_console {
    struct tty tty;
    struct vt* vt;
    int mode;
};

static struct virtual_console* consoles[NUM_CONSOLES];
static _Atomic(struct virtual_console*) active_console;

// Protects the underlying screen, which is shared by all virtual_consoles
static struct spinlock screen_lock;

static void activate_console(size_t index) {
    if (index >= NUM_CONSOLES)
        return;

    struct virtual_console* console = consoles[index];
    if (active_console == console)
        return;

    SCOPED_LOCK(tty, &console->tty);
    vt_invalidate_all(console->vt);

    SCOPED_LOCK(spinlock, &screen_lock);
    vt_flush(console->vt);

    active_console = console;
}

static void on_raw(unsigned char scancode) {
    struct virtual_console* console = active_console;
    struct tty* tty = &console->tty;
    SCOPED_LOCK(tty, tty);
    if (console->mode == K_RAW) {
        char x = scancode;
        tty_emit(tty, &x, 1);
    }
}

static unsigned char modifiers;
extern unsigned short* key_maps[MAX_NR_KEYMAPS];
extern char* func_table[MAX_NR_FUNC];
static struct spinlock key_map_lock;

static void xlate(unsigned char keycode, bool down) {
    unsigned short key_sym;
    {
        SCOPED_LOCK(spinlock, &key_map_lock);
        const unsigned short* key_map = key_maps[modifiers];
        if (!key_map)
            return;
        key_sym = key_map[keycode];
    }

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
    SCOPED_LOCK(tty, tty);
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
    if (active_console == console) {
        SCOPED_LOCK(spinlock, &screen_lock);
        vt_flush(console->vt);
    }
}

// ANSI escape code color palette
static uint32_t default_palette[NUM_COLORS] = {
    0x000000, // black
    0xaa0000, // red
    0x00aa00, // green
    0xaa5500, // yellow
    0x0000aa, // blue
    0xaa00aa, // magenta
    0x00aaaa, // cyan
    0xaaaaaa, // white
    0x555555, // bright black
    0xff5555, // bright red
    0x55ff55, // bright green
    0xffff55, // bright yellow
    0x5555ff, // bright blue
    0xff55ff, // bright magenta
    0x55ffff, // bright cyan
    0xffffff, // bright white
};
static struct spinlock default_palette_lock;

static void set_font(struct virtual_console* console, struct font* font) {
    struct font* old_font;
    {
        SCOPED_LOCK(tty, &console->tty);
        old_font = vt_swap_font(console->vt, font);
    }
    font_unref(old_font);

    if (active_console == console) {
        SCOPED_LOCK(spinlock, &screen_lock);
        vt_flush(console->vt);
    }
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
        int mode;
        {
            SCOPED_LOCK(tty, tty);
            mode = console->mode;
        }
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
        SCOPED_LOCK(tty, tty);
        console->mode = mode;
        break;
    }
    case KDGKBENT: {
        struct kbentry entry;
        if (copy_from_user(&entry, (const void*)arg, sizeof(struct kbentry)))
            return -EFAULT;
        unsigned short value;
        {
            SCOPED_LOCK(spinlock, &key_map_lock);
            const unsigned short* key_map = key_maps[entry.kb_table];
            if (key_map) {
                value = U(key_map[entry.kb_index]);
                if (KTYP(value) >= NR_TYPES)
                    value = K_HOLE;
            } else {
                value = entry.kb_index ? K_HOLE : K_NOSUCHMAP;
            }
        }
        if (copy_to_user((unsigned char*)arg +
                             offsetof(struct kbentry, kb_value),
                         &value, sizeof(unsigned short)))
            return -EFAULT;
        break;
    }
    case KDSKBENT: {
        struct kbentry entry;
        if (copy_from_user(&entry, (const void*)arg, sizeof(struct kbentry)))
            return -EFAULT;
        if (!entry.kb_index && entry.kb_value == K_NOSUCHMAP) {
            if (entry.kb_table) {
                SCOPED_LOCK(spinlock, &key_map_lock);
                unsigned short* key_map = key_maps[entry.kb_table];
                if (key_map) {
                    key_maps[entry.kb_table] = NULL;
                    if (key_map[0] == U(K_ALLOCATED))
                        kfree(key_map);
                }
            }
        } else {
            if (KTYP(entry.kb_value) >= NR_TYPES)
                return -EINVAL;
            if (!entry.kb_index)
                return -EINVAL;

            // Allocate before disabling the interrupts
            unsigned short* new_key_map FREE(kfree) =
                kmalloc(sizeof(unsigned short) * NR_KEYS);

            SCOPED_LOCK(spinlock, &key_map_lock);
            unsigned short* key_map = key_maps[entry.kb_table];
            if (!key_map) {
                if (!new_key_map)
                    return -ENOMEM;
                key_map = TAKE_PTR(new_key_map);
                key_map[0] = U(K_ALLOCATED);
                for (size_t i = 1; i < NR_KEYS; ++i)
                    key_map[i] = U(K_HOLE);
                key_maps[entry.kb_table] = key_map;
            }
            key_map[entry.kb_index] = U(entry.kb_value);
        }
        break;
    }
    case KDFONTOP: {
        struct console_font_op font_op;
        if (copy_from_user(&font_op, (const void*)arg,
                           sizeof(struct console_font_op)))
            return -EFAULT;

        switch (font_op.op) {
        case KD_FONT_OP_SET:
        case KD_FONT_OP_SET_TALL: {
            if (!font_op.data || !font_op.width || !font_op.height)
                return -EINVAL;
            if (font_op.charcount > MAX_FONT_GLYPHS ||
                font_op.width > MAX_FONT_WIDTH ||
                font_op.height > MAX_FONT_HEIGHT)
                return -EINVAL;

            size_t hpitch = DIV_CEIL(font_op.width, 8);
            size_t vpitch = 32;
            if (font_op.op == KD_FONT_OP_SET_TALL)
                vpitch = font_op.height;
            if (vpitch < font_op.height)
                return -EINVAL;

            size_t size = hpitch * vpitch * font_op.charcount;
            if (size > MAX_FONT_SIZE)
                return -EINVAL;

            unsigned char* data FREE(kfree) = kmalloc(size);
            if (!data)
                return -ENOMEM;
            if (copy_from_user(data, font_op.data, size))
                return -EFAULT;

            struct font* font FREE(font) = kmalloc(sizeof(struct font));
            if (!font)
                return -ENOMEM;
            *font = (struct font){
                .meta = {.num_glyphs = font_op.charcount,
                         .width = font_op.width,
                         .height = font_op.height,
                         .hpitch = hpitch,
                         .vpitch = vpitch},
                .data = TAKE_PTR(data),
                .refcount = REFCOUNT_INIT_ONE,
            };

            set_font(console, font);
            break;
        }
        case KD_FONT_OP_GET:
        case KD_FONT_OP_GET_TALL: {
            struct font* font FREE(font) = vt_get_font(console->vt);
            if (!font)
                return -EINVAL;

            struct font_meta* meta = &font->meta;
            if (meta->width > font_op.width || meta->height > font_op.height)
                return -ENOSPC;

            unsigned vpitch = 32;
            if (font_op.op == KD_FONT_OP_GET_TALL)
                vpitch = meta->height;
            if (vpitch != meta->vpitch)
                return -EINVAL;

            font_op.width = meta->width;
            font_op.height = meta->height;
            font_op.charcount = meta->num_glyphs;

            if (font_op.data) {
                if (meta->num_glyphs > font_op.charcount)
                    return -ENOSPC;
                if (copy_to_user(font_op.data, font->data, font_size(font)))
                    return -EFAULT;
            }
            break;
        }
        case KD_FONT_OP_SET_DEFAULT:
            if (font_op.data) {
                // We have no named fonts
                return -ENOENT;
            }

            set_font(console, &default_font);

            struct font_meta* meta = &default_font.meta;
            font_op.width = meta->width;
            font_op.height = meta->height;
            break;
        case KD_FONT_OP_COPY:
        default:
            return -EINVAL;
        }

        if (copy_to_user((void*)arg, &font_op, sizeof(struct console_font_op)))
            return -EFAULT;
        break;
    }
    case GIO_CMAP: {
        unsigned char cmap[NUM_COLORS * 3];
        {
            SCOPED_LOCK(spinlock, &default_palette_lock);
            size_t i = 0;
            for (size_t c = 0; c < NUM_COLORS; ++c) {
                uint32_t color = default_palette[c];
                cmap[i++] = (color >> 16) & 0xff; // R
                cmap[i++] = (color >> 8) & 0xff;  // G
                cmap[i++] = color & 0xff;         // B
            }
        }

        if (copy_to_user((void*)arg, cmap, sizeof(cmap)))
            return -EFAULT;
        break;
    }
    case PIO_CMAP: {
        unsigned char cmap[NUM_COLORS * 3];
        if (copy_from_user(cmap, (const void*)arg, sizeof(cmap)))
            return -EFAULT;

        {
            SCOPED_LOCK(spinlock, &default_palette_lock);
            size_t i = 0;
            for (size_t c = 0; c < NUM_COLORS; ++c) {
                uint32_t color = 0;
                color |= cmap[i++] << 16; // R
                color |= cmap[i++] << 8;  // G
                color |= cmap[i++];       // B
                default_palette[c] = color;
            }
            for (i = 0; i < NUM_CONSOLES; ++i) {
                struct virtual_console* console = consoles[i];
                SCOPED_LOCK(tty, &console->tty);
                vt_set_palette(console->vt, default_palette);
            }
        }

        SCOPED_LOCK(spinlock, &screen_lock);
        vt_flush(active_console->vt);
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
    vt_set_palette(console->vt, default_palette);

    static const struct tty_ops tty_ops = {
        .echo = virtual_console_echo,
        .ioctl = virtual_console_ioctl,
    };

    struct tty* tty = &console->tty;
    (void)snprintf(tty->name, sizeof(tty->name), "tty%u", tty_num);
    tty->dev = makedev(TTY_MAJOR, tty_num);
    tty->ops = &tty_ops;
    screen->get_size(&tty->num_columns, &tty->num_rows);

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
