#include "hid.h"
#include <kernel/api/hid.h>
#include <kernel/api/stat.h>
#include <kernel/api/sysmacros.h>
#include <kernel/console/console.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts.h>
#include <kernel/kmalloc.h>
#include <kernel/panic.h>
#include <kernel/scheduler.h>
#include <string.h>

#define QUEUE_SIZE 128

// en-US
static const char scancode_to_key[256] = {
    0,   0,    '1',  '2', '3',  '4', '5', '6', '7', '8', '9', '0', '-',
    '=', '\b', '\t', 'q', 'w',  'e', 'r', 't', 'y', 'u', 'i', 'o', 'p',
    '[', ']',  '\n', 0,   'a',  's', 'd', 'f', 'g', 'h', 'j', 'k', 'l',
    ';', '\'', '`',  0,   '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',',
    '.', '/',  0,    '*', 0,    ' ', 0,   0,   0,   0,   0,   0,   0,
    0,   0,    0,    0,   0,    0,   '7', '8', '9', '-', '4', '5', '6',
    '+', '1',  '2',  '3', '0',  '.', 0,   0,   '\\'};
static const char scancode_to_shifted_key[256] = {
    0,   0,    '!',  '@', '#', '$', '%', '^', '&', '*', '(', ')', '_',
    '+', '\b', '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P',
    '{', '}',  '\n', 0,   'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L',
    ':', '"',  '~',  0,   '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<',
    '>', '?',  0,    '*', 0,   ' ', 0,   0,   0,   0,   0,   0,   0,
    0,   0,    0,    0,   0,   0,   '7', '8', '9', '-', '4', '5', '6',
    '+', '1',  '2',  '3', '0', '.', 0,   0,   '|'};

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

static key_event queue[QUEUE_SIZE];
static size_t queue_head = 0;
static size_t queue_tail = 0;

static void irq_handler(registers* reg) {
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

    key_event* event = queue + queue_tail;
    queue_tail = (queue_tail + 1) % QUEUE_SIZE;

    event->scancode = ch;
    if (received_e0)
        event->scancode |= 0xe000;
    event->key = to_key[ch];
    event->modifiers = modifiers;
    event->pressed = pressed;

    received_e0 = false;

    tty_on_key(event);
}

void ps2_keyboard_init(void) {
    idt_register_interrupt_handler(IRQ(1), irq_handler);
}

static bool read_should_unblock(void) {
    bool int_flag = push_cli();
    bool should_unblock = queue_head != queue_tail;
    pop_cli(int_flag);
    return should_unblock;
}

static ssize_t ps2_keyboard_device_read(file_description* desc, void* buffer,
                                        size_t count) {
    (void)desc;

    size_t nread = 0;
    key_event* out = (key_event*)buffer;
    scheduler_block(read_should_unblock, NULL);

    bool int_flag = push_cli();

    while (count > 0) {
        if (queue_head == queue_tail || count < sizeof(key_event))
            break;
        *out++ = queue[queue_head];
        nread += sizeof(key_event);
        count -= sizeof(key_event);
        queue_head = (queue_head + 1) % QUEUE_SIZE;
    }

    pop_cli(int_flag);

    return nread;
}

struct file* ps2_keyboard_device_create(void) {
    struct file* file = kmalloc(sizeof(struct file));
    if (!file)
        return ERR_PTR(-ENOMEM);
    *file = (struct file){0};

    file->name = kstrdup("ps2_keyboard_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFCHR;
    file->read = ps2_keyboard_device_read;
    file->device_id = makedev(85, 0);
    return file;
}
