#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NUM_COLORS 16

struct screen {
    void (*get_size)(size_t* out_columns, size_t* out_rows);
    void (*put)(size_t x, size_t y, char c, uint8_t fg_color, uint8_t bg_color);
    void (*clear)(uint8_t bg_color);

    void (*set_cursor)(size_t x, size_t y, bool visible);
};

struct screen* screen_init(void);
