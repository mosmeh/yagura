#pragma once

#include <common/stdint.h>

#define MOUSE_BUTTON_LEFT 0x1
#define MOUSE_BUTTON_RIGHT 0x2
#define MOUSE_BUTTON_MIDDLE 0x4

struct moused_event {
    uint32_t x;
    uint32_t y;
    int16_t dx;
    int16_t dy;
    uint8_t buttons;
};
