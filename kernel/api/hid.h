#pragma once

#include <stdbool.h>
#include <stdint.h>

#define KEY_MODIFIER_ALT 0x1
#define KEY_MODIFIER_CTRL 0x2
#define KEY_MODIFIER_SHIFT 0x4
#define KEY_MODIFIER_SUPER 0x8
#define KEY_MODIFIER_ALTGR 0x10

typedef struct key_event {
    uint16_t scancode;
    uint8_t modifiers;
    char key;
    bool pressed;
} key_event;

#define MOUSE_BUTTON_LEFT 0x1
#define MOUSE_BUTTON_RIGHT 0x2
#define MOUSE_BUTTON_MIDDLE 0x4

typedef struct mouse_packet {
    int16_t dx;
    int16_t dy;
    uint8_t buttons;
} mouse_packet;
