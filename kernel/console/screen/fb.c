#include "psf.h"
#include "screen.h"
#include <kernel/drivers/graphics/graphics.h>
#include <kernel/kprintf.h>
#include <kernel/panic.h>
#include <kernel/process.h>

static const uint32_t palette[] = {
    0x191919, // black
    0x3465a4, // blue
    0x4e9a06, // green
    0x06989a, // cyan
    0xcc0000, // red
    0x75507b, // magenta
    0xc4a000, // brown
    0xd0d0d0, // light gray
    0x555753, // dark gray
    0x729fcf, // light blue
    0x8ae234, // light green
    0x34e2e2, // light cyan
    0xef2929, // light red
    0xad7fa8, // light magenta
    0xfce94f, // yellow
    0xeeeeec, // white
};

static struct font* font;
static unsigned char* fb;
static struct fb_info fb_info;
static size_t num_columns;
static size_t num_rows;
static size_t cursor_x;
static size_t cursor_y;
static bool is_cursor_visible;

static void get_size(struct screen* screen, size_t* out_columns,
                     size_t* out_rows) {
    (void)screen;
    *out_columns = num_columns;
    *out_rows = num_rows;
}

static void put(struct screen* screen, size_t x, size_t y, char c,
                uint8_t fg_color, uint8_t bg_color) {
    (void)screen;

    bool is_cursor = is_cursor_visible && x == cursor_x && y == cursor_y;
    uint32_t fg = palette[is_cursor ? bg_color : fg_color];
    uint32_t bg = palette[is_cursor ? fg_color : bg_color];

    const unsigned char* glyph =
        font->glyphs + font->ascii_to_glyph[(size_t)c] * font->bytes_per_glyph;
    unsigned char* row = fb + x * font->glyph_width * sizeof(uint32_t) +
                         y * font->glyph_height * fb_info.pitch;
    for (size_t py = 0; py < font->glyph_height; ++py) {
        uint32_t* pixel = (uint32_t*)row;
        for (size_t px = 0; px < font->glyph_width; ++px) {
            uint32_t val = *(const uint32_t*)glyph;
            uint32_t swapped = ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) |
                               ((val >> 8) & 0xff00) |
                               ((val << 24) & 0xff000000);
            *pixel++ = swapped & (1 << (32 - px - 1)) ? fg : bg;
        }
        glyph += font->bytes_per_glyph / font->glyph_height;
        row += fb_info.pitch;
    }
}

static void set_cursor(struct screen* screen, size_t x, size_t y,
                       bool visible) {
    (void)screen;
    cursor_x = x;
    cursor_y = y;
    is_cursor_visible = visible;
}

static void clear(struct screen* screen, uint8_t bg_color) {
    (void)screen;
    memset32((uint32_t*)fb, palette[bg_color],
             fb_info.pitch * fb_info.height / sizeof(uint32_t));
}

static struct screen fb_screen = {
    .get_size = get_size,
    .put = put,
    .set_cursor = set_cursor,
    .clear = clear,
};

struct screen* fb_screen_init(void) {
    if (!fb_get())
        return ERR_PTR(-ENODEV);

    const char* font_pathname = cmdline_lookup("font");
    if (!font_pathname)
        font_pathname = "/usr/share/fonts/default.psf";

    int rc = fb_get()->get_info(&fb_info);
    if (IS_ERR(rc)) {
        kprintf("fb_screen: failed to get framebuffer info\n");
        return ERR_PTR(rc);
    }
    if (fb_info.bpp != 32) {
        kprintf("fb_screen: unsupported framebuffer bpp=%u\n", fb_info.bpp);
        return ERR_PTR(-ENOTSUP);
    }

    font = load_psf(font_pathname);
    if (IS_ERR(font)) {
        kprintf("fb_screen: failed to load font file %s\n", font_pathname);
        return ERR_CAST(font);
    }

    num_columns = fb_info.width / font->glyph_width;
    num_rows = fb_info.height / font->glyph_height;
    kprintf("fb_screen: columns=%u rows=%u\n", num_columns, num_rows);

    size_t fb_size = fb_info.pitch * fb_info.height;
    fb = fb_get()->mmap(fb_size, 0, VM_READ | VM_WRITE | VM_SHARED);
    if (IS_ERR(fb)) {
        kprintf("fb_screen: failed to mmap framebuffer\n");
        return ERR_CAST(fb);
    }

    return &fb_screen;
}
