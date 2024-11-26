#include "screen.h"
#include <kernel/asm_wrapper.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>

#define NUM_COLUMNS 80
#define NUM_ROWS 25

#define VGA_CRTC_INDEX 0x3d4
#define VGA_CRTC_DATA 0x3d5

static uint16_t* cells;

static void get_size(struct screen* screen, size_t* out_columns,
                     size_t* out_rows) {
    (void)screen;
    *out_columns = NUM_COLUMNS;
    *out_rows = NUM_ROWS;
}

static void put(struct screen* screen, size_t x, size_t y, char c,
                uint8_t fg_color, uint8_t bg_color) {
    (void)screen;
    uint16_t* cell = cells + y * NUM_COLUMNS + x;
    *cell = c | ((uint16_t)fg_color << 8) | ((uint16_t)bg_color << 12);
}

static void set_cursor(struct screen* screen, size_t x, size_t y,
                       bool visible) {
    (void)screen;
    if (visible) {
        uint16_t value = y * NUM_COLUMNS + x;
        out8(VGA_CRTC_INDEX, 0xe);
        out8(VGA_CRTC_DATA, value >> 8);
        out8(VGA_CRTC_INDEX, 0xf);
        out8(VGA_CRTC_DATA, value & 0xff);
    }
    out8(VGA_CRTC_INDEX, 0xa);
    out8(VGA_CRTC_DATA, visible ? 0 : 0x20);
}

static void clear(struct screen* screen, uint8_t bg_color) {
    (void)screen;
    memset16(cells, (uint16_t)bg_color << 12, NUM_COLUMNS * NUM_ROWS);
}

static struct screen screen = {
    .get_size = get_size,
    .put = put,
    .set_cursor = set_cursor,
    .clear = clear,
};

struct screen* vga_text_screen_init(void) {
    cells = phys_map(0xb8000, NUM_COLUMNS * NUM_ROWS * 2,
                     VM_READ | VM_WRITE | VM_WC);
    if (IS_ERR(cells))
        return ERR_CAST(cells);
    return &screen;
}
