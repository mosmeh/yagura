#pragma once

#include "forward.h"
#include <stdint.h>

#define MOUSE_BUTTON_LEFT 0x1
#define MOUSE_BUTTON_RIGHT 0x2
#define MOUSE_BUTTON_MIDDLE 0x4

typedef struct mouse_packet {
    int16_t dx;
    int16_t dy;
    uint8_t buttons;
} mouse_packet;

void ps2_mouse_init(void);
fs_node* ps2_mouse_device_create(void);
