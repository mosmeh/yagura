#pragma once

#include <kernel/memory/memory.h>

#define MAX_FONT_WIDTH 64
#define MAX_FONT_HEIGHT 128
#define MAX_FONT_GLYPHS 512
#define MAX_FONT_SIZE (MAX_FONT_GLYPHS * MAX_FONT_WIDTH * MAX_FONT_HEIGHT)

extern struct font default_font;

struct font_meta {
    size_t num_glyphs;

    // Glyph size in pixels
    size_t width, height;

    // Horizontal and vertical pitch in bytes
    // Each glyph takes up hpitch * vpitch bytes
    size_t hpitch, vpitch;
};

struct font {
    struct font_meta meta;
    unsigned char* data;
    refcount_t refcount;
};

static inline void __font_destroy(struct font* font) {
    kfree(font->data);
    kfree(font);
}

DEFINE_REFCOUNTED_BASE(font, struct font*, refcount, __font_destroy)

// Returns the size in bytes of the font data
static inline size_t font_size(const struct font* font) {
    const struct font_meta* meta = &font->meta;
    return meta->hpitch * meta->vpitch * meta->num_glyphs;
}
