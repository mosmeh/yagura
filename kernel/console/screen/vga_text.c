#include <common/bytes.h>
#include <common/string.h>
#include <kernel/asm_wrapper.h>
#include <kernel/console/screen/screen.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>

#define NUM_COLUMNS 80
#define NUM_ROWS 25

#define VGA_SEQ_INDEX 0x3c4
#define VGA_SEQ_DATA 0x3c5
#define VGA_DAC_WRITE_INDEX 0x3c8
#define VGA_DAC_DATA 0x3c9
#define VGA_GC_INDEX 0x3ce
#define VGA_GC_DATA 0x3cf
#define VGA_CRTC_INDEX 0x3d4
#define VGA_CRTC_DATA 0x3d5

#define VGA_FONT_WIDTH 8
#define VGA_MAX_FONT_HEIGHT 32
#define VGA_FONT_VPITCH 32
#define VGA_MAX_FONT_GLYPHS 256

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

// Plane 0 and plane 1 are accessed as odd and even bytes respectively,
// so each 16-bit value represents one character cell:
// - 1st byte: plane 0 (character)
// - 2nd byte: plane 1 (attributes)
static uint16_t* cells;

// For plane 2 (font).
// Note font data can be only accessed when VGA is configured to access plane 2,
// which is done in set_font().
static unsigned char* font_data;

static void write_seq(uint8_t index, uint8_t value) {
    out8(VGA_SEQ_INDEX, index);
    out8(VGA_SEQ_DATA, value);
}

static void write_crtc(uint8_t index, uint8_t value) {
    out8(VGA_CRTC_INDEX, index);
    out8(VGA_CRTC_DATA, value);
}

static void write_gc(uint8_t index, uint8_t value) {
    out8(VGA_GC_INDEX, index);
    out8(VGA_GC_DATA, value);
}

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
        write_crtc(0xe, value >> 8);
        write_crtc(0xf, value & 0xff);
    }
    write_crtc(0xa, visible ? 0 : 0x20);
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

static void set_font(const struct font* font) {
    if (!font) {
        // Setting default font is not supported
        return;
    }

    const struct font_meta* meta = &font->meta;
    if (meta->width != VGA_FONT_WIDTH || meta->height > VGA_MAX_FONT_HEIGHT ||
        meta->vpitch != VGA_FONT_VPITCH ||
        meta->num_glyphs > VGA_MAX_FONT_GLYPHS)
        return;

    write_seq(0x0, 0x1); // Synchronous reset
    write_seq(0x2, 0x4); // Write to plane 2
    write_seq(0x4, 0x7); // Disable odd/even addressing
    write_seq(0x0, 0x3); // Clear synchronous reset

    write_gc(0x4, 0x2); // Read plane 2
    write_gc(0x5, 0x0); // Disable odd/even addressing
    write_gc(0x6, 0x0); // Map at 0xa0000

    memcpy(font_data, font->data, font_size(font));

    write_seq(0x0, 0x1); // Synchronous reset
    write_seq(0x2, 0x3); // Write to planes 0 and 1
    write_seq(0x4, 0x3); // Enable odd/even addressing
    write_seq(0x0, 0x3); // Clear synchronous reset

    write_gc(0x4, 0x0);  // Read plane 0
    write_gc(0x5, 0x10); // Enable odd/even addressing
    write_gc(0x6, 0xe);  // Map at 0xb8000
}

static struct screen screen = {
    .get_size = get_size,
    .put = put,
    .clear = clear,
    .set_cursor = set_cursor,
    .set_palette = set_palette,
    .set_font = set_font,
};

struct screen* vga_text_screen_init(void) {
    cells = phys_map(0xb8000, NUM_COLUMNS * NUM_ROWS * 2,
                     VM_READ | VM_WRITE | VM_WC);
    if (IS_ERR(ASSERT(cells)))
        return ERR_CAST(cells);

    font_data = phys_map(
        0xa0000, VGA_FONT_WIDTH / 8 * VGA_FONT_VPITCH * VGA_MAX_FONT_GLYPHS,
        VM_READ | VM_WRITE);
    if (IS_ERR(ASSERT(font_data))) {
        phys_unmap(cells);
        return ERR_CAST(font_data);
    }

    return &screen;
}
