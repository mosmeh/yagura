#include <common/bytes.h>
#include <common/integer.h>
#include <common/string.h>
#include <kernel/console/screen/screen.h>
#include <kernel/drivers/graphics/graphics.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/task/task.h>

static uint32_t palette[NUM_COLORS];
static struct font_meta font_meta;
static unsigned char* font_data;

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
    if (y * font_meta.height >= fb_info.height ||
        x * font_meta.width >= fb_info.width) {
        return;
    }

    bool is_cursor = is_cursor_visible && x == cursor_x && y == cursor_y;
    uint32_t fg = palette[is_cursor ? bg_color : fg_color];
    uint32_t bg = palette[is_cursor ? fg_color : bg_color];

    const unsigned char* glyph_row =
        font_data + font_meta.hpitch * font_meta.vpitch * (size_t)c;
    size_t glyph_height =
        MIN(font_meta.height, fb_info.height - y * font_meta.height);
    size_t glyph_width =
        MIN(font_meta.width, fb_info.width - x * font_meta.width);

    unsigned char* fb_row = fb;
    fb_row += y * font_meta.height * fb_info.pitch;
    fb_row += x * font_meta.width * sizeof(uint32_t);

    for (size_t py = 0; py < glyph_height; ++py) {
        uint32_t* pixel = (uint32_t*)fb_row;
        for (size_t px = 0; px < glyph_width; ++px) {
            size_t byte_index = px / 8;
            size_t bit_index = 7 - (px % 8);
            bool is_fg = glyph_row[byte_index] & (1U << bit_index);
            *pixel++ = is_fg ? fg : bg;
        }
        glyph_row += font_meta.hpitch;
        fb_row += fb_info.pitch;
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

static void set_font(const struct font* font) {
    if (!font)
        font = &default_font;
    font_meta = font->meta;
    memcpy(font_data, font->data, font_size(font));
}

static struct screen fb_screen = {
    .get_size = get_size,
    .put = put,
    .clear = clear,
    .set_cursor = set_cursor,
    .set_palette = set_palette,
    .set_font = set_font,
};

struct screen* fb_screen_init(void) {
    if (!fb_get())
        return ERR_PTR(-ENODEV);

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

    font_data = kmalloc(MAX_FONT_SIZE);
    if (!font_data) {
        kprint("fb_screen: failed to allocate font buffer\n");
        return ERR_PTR(-ENOMEM);
    }
    set_font(&default_font);

    num_columns = fb_info.width / font_meta.width;
    num_rows = fb_info.height / font_meta.height;
    kprintf("fb_screen: columns=%u rows=%u\n", num_columns, num_rows);

    return &fb_screen;
}
