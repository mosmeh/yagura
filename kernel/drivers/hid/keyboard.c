#include "hid.h"
#include "ps2.h"
#include <kernel/api/hid.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/console/console.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/lock.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

#define QUEUE_SIZE 128

// Scan code set 1 to en-US
static const char scancode_to_key[256] = {
    0,   '\x1b', '1',  '2', '3',  '4', '5', '6', '7', '8', '9', '0', '-',
    '=', 0x7f,   '\t', 'q', 'w',  'e', 'r', 't', 'y', 'u', 'i', 'o', 'p',
    '[', ']',    '\n', 0,   'a',  's', 'd', 'f', 'g', 'h', 'j', 'k', 'l',
    ';', '\'',   '`',  0,   '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',',
    '.', '/',    0,    '*', 0,    ' ', 0,   0,   0,   0,   0,   0,   0,
    0,   0,      0,    0,   0,    0,   '7', '8', '9', '-', '4', '5', '6',
    '+', '1',    '2',  '3', '0',  '.', 0,   0,   '\\'};
static const char scancode_to_shifted_key[256] = {
    0,   '\x1b', '!',  '@', '#', '$', '%', '^', '&', '*', '(', ')', '_',
    '+', 0x7f,   '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P',
    '{', '}',    '\n', 0,   'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L',
    ':', '"',    '~',  0,   '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<',
    '>', '?',    0,    '*', 0,   ' ', 0,   0,   0,   0,   0,   0,   0,
    0,   0,      0,    0,   0,   0,   '7', '8', '9', '-', '4', '5', '6',
    '+', '1',    '2',  '3', '0', '.', 0,   0,   '|'};

static const uint8_t scancode_to_keycode[256] = {
    KEYCODE_NONE,
    KEYCODE_ESCAPE,
    KEYCODE_1,
    KEYCODE_2,
    KEYCODE_3,
    KEYCODE_4,
    KEYCODE_5,
    KEYCODE_6,
    KEYCODE_7,
    KEYCODE_8,
    KEYCODE_9,
    KEYCODE_0,
    KEYCODE_MINUS,
    KEYCODE_EQUALS,
    KEYCODE_BACKSPACE,
    KEYCODE_TAB,
    KEYCODE_Q,
    KEYCODE_W,
    KEYCODE_E,
    KEYCODE_R,
    KEYCODE_T,
    KEYCODE_Y,
    KEYCODE_U,
    KEYCODE_I,
    KEYCODE_O,
    KEYCODE_P,
    KEYCODE_LEFT_BRACKET,
    KEYCODE_RIGHT_BRACKET,
    KEYCODE_RETURN,
    KEYCODE_CONTROL,
    KEYCODE_A,
    KEYCODE_S,
    KEYCODE_D,
    KEYCODE_F,
    KEYCODE_G,
    KEYCODE_H,
    KEYCODE_J,
    KEYCODE_K,
    KEYCODE_L,
    KEYCODE_SEMICOLON,
    KEYCODE_QUOTE,
    KEYCODE_BACK_QUOTE,
    KEYCODE_LEFT_SHIFT,
    KEYCODE_BACKSLASH,
    KEYCODE_Z,
    KEYCODE_X,
    KEYCODE_C,
    KEYCODE_V,
    KEYCODE_B,
    KEYCODE_N,
    KEYCODE_M,
    KEYCODE_COMMA,
    KEYCODE_PERIOD,
    KEYCODE_SLASH,
    KEYCODE_RIGHT_SHIFT,
    KEYCODE_ASTERISK,
    KEYCODE_ALT,
    KEYCODE_SPACE,
    KEYCODE_CAPS_LOCK,
    KEYCODE_F1,
    KEYCODE_F2,
    KEYCODE_F3,
    KEYCODE_F4,
    KEYCODE_F5,
    KEYCODE_F6,
    KEYCODE_F7,
    KEYCODE_F8,
    KEYCODE_F9,
    KEYCODE_F10,
    KEYCODE_NUMLOCK,
    KEYCODE_NONE,
    KEYCODE_HOME,
    KEYCODE_UP,
    KEYCODE_PAGE_UP,
    KEYCODE_MINUS,
    KEYCODE_LEFT,
    KEYCODE_NONE,
    KEYCODE_RIGHT,
    KEYCODE_PLUS,
    KEYCODE_END,
    KEYCODE_DOWN,
    KEYCODE_PAGE_DOWN,
    KEYCODE_NONE,
    KEYCODE_DELETE,
    KEYCODE_NONE,
    KEYCODE_NONE,
    KEYCODE_BACKSLASH,
    KEYCODE_F11,
    KEYCODE_F12,
    KEYCODE_NONE,
    KEYCODE_NONE,
    KEYCODE_SUPER,
    KEYCODE_NONE,
    KEYCODE_MENU,
};

static const uint8_t scancode_to_shifted_keycode[256] = {
    KEYCODE_NONE,
    KEYCODE_ESCAPE,
    KEYCODE_EXCLAIM,
    KEYCODE_AT,
    KEYCODE_HASH,
    KEYCODE_DOLLAR,
    KEYCODE_PERCENT,
    KEYCODE_CARET,
    KEYCODE_AMPERSAND,
    KEYCODE_ASTERISK,
    KEYCODE_LEFT_PAREN,
    KEYCODE_RIGHT_PAREN,
    KEYCODE_UNDERSCORE,
    KEYCODE_PLUS,
    KEYCODE_BACKSPACE,
    KEYCODE_TAB,
    KEYCODE_Q,
    KEYCODE_W,
    KEYCODE_E,
    KEYCODE_R,
    KEYCODE_T,
    KEYCODE_Y,
    KEYCODE_U,
    KEYCODE_I,
    KEYCODE_O,
    KEYCODE_P,
    KEYCODE_LEFT_CURLY_BRACKET,
    KEYCODE_RIGHT_CURLY_BRACKET,
    KEYCODE_RETURN,
    KEYCODE_CONTROL,
    KEYCODE_A,
    KEYCODE_S,
    KEYCODE_D,
    KEYCODE_F,
    KEYCODE_G,
    KEYCODE_H,
    KEYCODE_J,
    KEYCODE_K,
    KEYCODE_L,
    KEYCODE_COLON,
    KEYCODE_DOUBLE_QUOTE,
    KEYCODE_TILDE,
    KEYCODE_LEFT_SHIFT,
    KEYCODE_PIPE,
    KEYCODE_Z,
    KEYCODE_X,
    KEYCODE_C,
    KEYCODE_V,
    KEYCODE_B,
    KEYCODE_N,
    KEYCODE_M,
    KEYCODE_LESS,
    KEYCODE_GREATER,
    KEYCODE_QUESTION,
    KEYCODE_RIGHT_SHIFT,
    KEYCODE_ASTERISK,
    KEYCODE_ALT,
    KEYCODE_SPACE,
    KEYCODE_CAPS_LOCK,
    KEYCODE_F1,
    KEYCODE_F2,
    KEYCODE_F3,
    KEYCODE_F4,
    KEYCODE_F5,
    KEYCODE_F6,
    KEYCODE_F7,
    KEYCODE_F8,
    KEYCODE_F9,
    KEYCODE_F10,
    KEYCODE_NUMLOCK,
    KEYCODE_NONE,
    KEYCODE_HOME,
    KEYCODE_UP,
    KEYCODE_PAGE_UP,
    KEYCODE_MINUS,
    KEYCODE_LEFT,
    KEYCODE_NONE,
    KEYCODE_RIGHT,
    KEYCODE_PLUS,
    KEYCODE_END,
    KEYCODE_DOWN,
    KEYCODE_PAGE_DOWN,
    KEYCODE_NONE,
    KEYCODE_DELETE,
    KEYCODE_NONE,
    KEYCODE_NONE,
    KEYCODE_PIPE,
    KEYCODE_F11,
    KEYCODE_F12,
    KEYCODE_NONE,
    KEYCODE_NONE,
    KEYCODE_SUPER,
    KEYCODE_NONE,
    KEYCODE_MENU,
};

static bool received_e0 = false;

#define STATE_ALT 0x1
#define STATE_CTRL 0x2
#define STATE_LEFT_SHIFT 0x4
#define STATE_RIGHT_SHIFT 0x8
#define STATE_LEFT_SUPER 0x10
#define STATE_RIGHT_SUPER 0x20
#define STATE_ALTGR 0x40

static uint8_t state = 0;
static void set_state(uint8_t which, bool pressed) {
    if (pressed)
        state |= which;
    else
        state &= ~which;
}

static struct key_event queue[QUEUE_SIZE];
static size_t queue_read_idx = 0;
static size_t queue_write_idx = 0;
static struct spinlock queue_lock;

static ps2_key_event_handler_fn event_handler = NULL;

static void irq_handler(struct registers* reg) {
    (void)reg;

    uint8_t data = in8(PS2_DATA);
    if (data == 0xe0) {
        received_e0 = true;
        return;
    }

    unsigned char ch = data & 0x7f;
    bool pressed = !(data & 0x80);

    switch (ch) {
    case 0x38:
        set_state(received_e0 ? STATE_ALTGR : STATE_ALT, pressed);
        break;
    case 0x1d:
        set_state(STATE_CTRL, pressed);
        break;
    case 0x5b:
        set_state(STATE_LEFT_SUPER, pressed);
        break;
    case 0x5c:
        set_state(STATE_RIGHT_SUPER, pressed);
        break;
    case 0x2a:
        set_state(STATE_LEFT_SHIFT, pressed);
        break;
    case 0x36:
        set_state(STATE_RIGHT_SHIFT, pressed);
        break;
    }

    uint8_t modifiers = 0;
    if (state & STATE_ALT)
        modifiers |= KEY_MODIFIER_ALT;
    if (state & STATE_CTRL)
        modifiers |= KEY_MODIFIER_CTRL;
    if (state & (STATE_LEFT_SHIFT | STATE_RIGHT_SHIFT))
        modifiers |= KEY_MODIFIER_SHIFT;
    if (state & (STATE_LEFT_SUPER | STATE_RIGHT_SUPER))
        modifiers |= KEY_MODIFIER_SUPER;
    if (state & STATE_ALTGR)
        modifiers |= KEY_MODIFIER_ALTGR;

    const char* to_key = (modifiers & KEY_MODIFIER_SHIFT)
                             ? scancode_to_shifted_key
                             : scancode_to_key;
    const uint8_t* to_keycode = (modifiers & KEY_MODIFIER_SHIFT)
                                    ? scancode_to_shifted_keycode
                                    : scancode_to_keycode;

    struct key_event event = {
        .scancode = ch,
        .key = to_key[ch],
        .keycode = to_keycode[ch],
        .modifiers = modifiers,
        .pressed = pressed,
    };
    if (received_e0)
        event.scancode |= 0xe000;

    received_e0 = false;

    if (event_handler)
        event_handler(&event);

    spinlock_lock(&queue_lock);
    *(queue + queue_write_idx) = event;
    queue_write_idx = (queue_write_idx + 1) % QUEUE_SIZE;
    spinlock_unlock(&queue_lock);
}

void ps2_set_key_event_handler(ps2_key_event_handler_fn handler) {
    event_handler = handler;
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

static ssize_t ps2_keyboard_device_pread(struct file* file, void* buffer,
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
        struct key_event* out = (struct key_event*)buffer;
        while (count > 0) {
            if (queue_read_idx == queue_write_idx ||
                count < sizeof(struct key_event))
                break;
            *out++ = queue[queue_read_idx];
            nread += sizeof(struct key_event);
            count -= sizeof(struct key_event);
            queue_read_idx = (queue_read_idx + 1) % QUEUE_SIZE;
        }
        spinlock_unlock(&queue_lock);
        return nread;
    }
}

static short ps2_keyboard_device_poll(struct file* file, short events) {
    (void)file;
    short revents = 0;
    if ((events & POLLIN) && can_read())
        revents |= POLLIN;
    if (events & POLLOUT)
        revents |= POLLOUT;
    return revents;
}

static struct inode* ps2_keyboard_device_get(void) {
    static const struct file_ops fops = {
        .pread = ps2_keyboard_device_pread,
        .poll = ps2_keyboard_device_poll,
    };
    static struct inode inode = {
        .vm_obj = INODE_VM_OBJ_CONST_INIT,
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(11, 0),
    };
    return &inode;
}

void ps2_keyboard_init(void) {
    ps2_write(PS2_COMMAND, PS2_ENABLE_PORT1);
    idt_set_interrupt_handler(IRQ(1), irq_handler);

    ASSERT_OK(vfs_register_device("kbd", ps2_keyboard_device_get()));
}
