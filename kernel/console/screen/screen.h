#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct screen {
    void (*get_size)(struct screen*, size_t* out_columns, size_t* out_rows);
    void (*put)(struct screen*, size_t x, size_t y, char c, uint8_t fg_color,
                uint8_t bg_color);
    void (*set_cursor)(struct screen*, size_t x, size_t y, bool visible);
    void (*clear)(struct screen*, uint8_t bg_color);
};

struct screen* screen_init(void);
