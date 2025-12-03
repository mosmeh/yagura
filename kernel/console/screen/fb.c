#include "psf.h"
#include "screen.h"
#include <common/string.h>
#include <kernel/drivers/graphics/graphics.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/task.h>

static uint32_t palette[NUM_COLORS];
static struct font* font;
static unsigned char* fb;
static struct fb_info fb_info;
static size_t num_columns;
static size_t num_rows;
static size_t cursor_x;
static size_t cursor_y;
static bool is_cursor_visible;

static void get_size(size_t* out_columns, size_t* out_rows) {
    if (out_columns)
        *out_columns = num_columns;
    if (out_rows)
        *out_rows = num_rows;
}

static void put(size_t x, size_t y, char c, uint8_t fg_color,
                uint8_t bg_color) {
    bool is_cursor = is_cursor_visible && x == cursor_x && y == cursor_y;
    uint32_t fg = palette[is_cursor ? bg_color : fg_color];
    uint32_t bg = palette[is_cursor ? fg_color : bg_color];

    const unsigned char* glyph =
        font->glyphs + font->ascii_to_glyph[(size_t)c] * font->bytes_per_glyph;
    unsigned char* row = fb;
    row += y * font->glyph_height * fb_info.pitch;
    row += x * font->glyph_width * sizeof(uint32_t);
    for (size_t py = 0; py < font->glyph_height; ++py) {
        uint32_t* pixel = (uint32_t*)row;
        uint32_t v = ((uint32_t)glyph[0] << 24) | ((uint32_t)glyph[1] << 16) |
                     ((uint32_t)glyph[2] << 8) | glyph[3];
        for (size_t px = 0; px < font->glyph_width; ++px)
            *pixel++ = v & (1U << (32 - px - 1)) ? fg : bg;
        glyph += font->bytes_per_glyph / font->glyph_height;
        row += fb_info.pitch;
    }
}

static void clear(uint8_t bg_color) {
    memset32((uint32_t*)fb, palette[bg_color],
             fb_info.pitch * fb_info.height / sizeof(uint32_t));
}

static void set_cursor(size_t x, size_t y, bool visible) {
    cursor_x = x;
    cursor_y = y;
    is_cursor_visible = visible;
}

static void set_palette(const uint32_t new_palette[NUM_COLORS]) {
    memcpy(palette, new_palette, sizeof(palette));
}

static struct screen fb_screen = {
    .get_size = get_size,
    .put = put,
    .clear = clear,
    .set_cursor = set_cursor,
    .set_palette = set_palette,
};

struct screen* fb_screen_init(void) {
    if (!fb_get())
        return ERR_PTR(-ENODEV);

    const char* font_pathname = cmdline_lookup("font");
    if (!font_pathname)
        font_pathname = "/usr/share/fonts/default.psf";

    int rc = fb_get()->get_info(&fb_info);
    if (IS_ERR(rc)) {
        kprint("fb_screen: failed to get framebuffer info\n");
        return ERR_PTR(rc);
    }
    if (fb_info.bpp != 32) {
        kprintf("fb_screen: unsupported framebuffer bpp=%u\n", fb_info.bpp);
        return ERR_PTR(-ENOTSUP);
    }

    struct vm_obj* vm_obj FREE(vm_obj) = fb_mmap();
    size_t npages = DIV_CEIL(fb_info.pitch * fb_info.height, PAGE_SIZE);
    fb = vm_obj_map(vm_obj, 0, npages, VM_READ | VM_WRITE | VM_SHARED);
    if (IS_ERR(ASSERT(fb))) {
        kprint("fb_screen: failed to map framebuffer\n");
        return ERR_CAST(fb);
    }

    font = load_psf(font_pathname);
    if (IS_ERR(ASSERT(font))) {
        kprintf("fb_screen: failed to load font file %s\n", font_pathname);
        return ERR_CAST(font);
    }

    num_columns = fb_info.width / font->glyph_width;
    num_rows = fb_info.height / font->glyph_height;
    kprintf("fb_screen: columns=%u rows=%u\n", num_columns, num_rows);

    return &fb_screen;
}
