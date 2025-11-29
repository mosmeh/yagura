#pragma once

#include <stdint.h>

#define MOUSE_BUTTON_LEFT 0x1
#define MOUSE_BUTTON_RIGHT 0x2
#define MOUSE_BUTTON_MIDDLE 0x4

struct mouse_event {
    int16_t dx;
    int16_t dy;
    uint8_t buttons;
};
