#pragma once

#include <hid.h>

typedef struct moused_event {
    uint32_t x;
    uint32_t y;
    int16_t dx;
    int16_t dy;
    uint8_t buttons;
} moused_event;
