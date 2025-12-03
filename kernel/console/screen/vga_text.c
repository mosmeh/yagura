#include "screen.h"
#include <kernel/asm_wrapper.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>

#define NUM_COLUMNS 80
#define NUM_ROWS 25

#define VGA_DAC_WRITE_INDEX 0x3c8
#define VGA_DAC_DATA 0x3c9
#define VGA_CRTC_INDEX 0x3d4
#define VGA_CRTC_DATA 0x3d5

static const uint16_t to_vga_color[] = {
    0,  // black
    4,  // read
    2,  // green
    6,  // brown
    1,  // blue
    5,  // magenta
    3,  // cyan
    7,  // light gray
    8,  // dark gray
    12, // light blue
    10, // light green
    14, // light cyan
    9,  // light red
    13, // light magenta
    11, // yellow
    15, // white
};

static uint16_t* cells;

static void get_size(size_t* out_columns, size_t* out_rows) {
    if (out_columns)
        *out_columns = NUM_COLUMNS;
    if (out_rows)
        *out_rows = NUM_ROWS;
}

static void put(size_t x, size_t y, char c, uint8_t fg_color,
                uint8_t bg_color) {
    uint16_t* cell = cells + y * NUM_COLUMNS + x;
    *cell = c | (to_vga_color[fg_color] << 8) | (to_vga_color[bg_color] << 12);
}

static void clear(uint8_t bg_color) {
    memset16(cells, to_vga_color[bg_color] << 12, NUM_COLUMNS * NUM_ROWS);
}

static void set_cursor(size_t x, size_t y, bool visible) {
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

static void set_palette(const uint32_t palette[NUM_COLORS]) {
    for (size_t i = 0; i < NUM_COLORS; ++i) {
        uint32_t c = palette[i];
        unsigned char r = (c >> 16) & 0xff;
        unsigned char g = (c >> 8) & 0xff;
        unsigned char b = c & 0xff;

        out8(VGA_DAC_WRITE_INDEX, to_vga_color[i]);
        // VGA colors are 6 bits per channel. Use the upper 6 bits.
        out8(VGA_DAC_DATA, r >> 2);
        out8(VGA_DAC_DATA, g >> 2);
        out8(VGA_DAC_DATA, b >> 2);
    }
}

static struct screen screen = {
    .get_size = get_size,
    .put = put,
    .clear = clear,
    .set_cursor = set_cursor,
    .set_palette = set_palette,
};

struct screen* vga_text_screen_init(void) {
    cells = phys_map(0xb8000, NUM_COLUMNS * NUM_ROWS * 2,
                     VM_READ | VM_WRITE | VM_WC);
    if (IS_ERR(ASSERT(cells)))
        return ERR_CAST(cells);
    return &screen;
}
