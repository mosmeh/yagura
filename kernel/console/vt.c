#include "private.h"
#include <common/integer.h>
#include <common/stdlib.h>
#include <common/string.h>
#include <kernel/console/screen/screen.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

#define TAB_STOP 8

// ANSI escape code colors
#define DEFAULT_FG_COLOR 7 // White
#define DEFAULT_BG_COLOR 0 // Black
#define ITALIC_COLOR 2     // Green
#define UNDERLINE_COLOR 6  // Cyan
#define FAINT_COLOR 8      // Bright black
#define COLOR_BRIGHT 0x8

struct cell {
    char ch;
    uint8_t fg_color;
    uint8_t bg_color;
    bool dirty;
};

#define VT_STOMP 0x1
#define VT_CURSOR_VISIBLE 0x2
#define VT_ITALIC 0x4
#define VT_UNDERLINE 0x8
#define VT_BLINK 0x10
#define VT_COLOR_REVERSED 0x20

#define VT_WHOLE_SCREEN_DIRTY 0x100
#define VT_CURSOR_DIRTY 0x200
#define VT_PALETTE_DIRTY 0x400
#define VT_FONT_DIRTY 0x800

#define VT_ALL_DIRTY                                                           \
    (VT_WHOLE_SCREEN_DIRTY | VT_CURSOR_DIRTY | VT_PALETTE_DIRTY | VT_FONT_DIRTY)

enum {
    VT_INTENSITY_NORMAL,
    VT_INTENSITY_BOLD,
    VT_INTENSITY_FAINT,
};

struct vt {
    struct screen* screen;

    size_t num_columns;
    size_t num_rows;

    size_t cursor_x;
    size_t cursor_y;

    enum state {
        STATE_GROUND,
        STATE_ESC,
        STATE_CSI,
        STATE_CSI_ECMA,
        STATE_CSI_DEC,
        STATE_OSC,
        STATE_OSC_PALETTE,
    } state;
    unsigned params[16];
    size_t num_params;

    uint32_t palette[NUM_COLORS];
    uint8_t fg_color;
    uint8_t bg_color;
    struct font* font;

    struct cell* cells;
    unsigned flags;
    unsigned char intensity;
};

static void invalidate_cell(struct vt* vt, size_t x, size_t y) {
    ASSERT(x < vt->num_columns);
    ASSERT(y < vt->num_rows);
    vt->cells[x + y * vt->num_columns].dirty = true;
}

static void set_cursor(struct vt* vt, size_t x, size_t y) {
    ASSERT(x < vt->num_columns);
    ASSERT(y < vt->num_rows);

    // Even if the cursor position won't actually change, the cursor is
    // logically "moved" by the command, so we need to clear the stomp flag.
    vt->flags &= ~VT_STOMP;

    if (vt->cursor_x == x && vt->cursor_y == y)
        return;

    invalidate_cell(vt, vt->cursor_x, vt->cursor_y);
    invalidate_cell(vt, x, y);
    vt->cursor_x = x;
    vt->cursor_y = y;
    vt->flags |= VT_CURSOR_DIRTY;
}

static void clear_line_at(struct vt* vt, size_t x, size_t y, size_t length) {
    ASSERT(x < vt->num_columns);
    ASSERT(y < vt->num_rows);
    ASSERT(x + length <= vt->num_columns);

    struct cell* cell = vt->cells + x + y * vt->num_columns;
    for (size_t i = 0; i < length; ++i, ++cell) {
        // VT_COLOR_REVERSED doesn't affect clearing.
        if (cell->ch == ' ' && cell->fg_color == vt->fg_color &&
            cell->bg_color == vt->bg_color)
            continue;
        cell->ch = ' ';
        cell->fg_color = vt->fg_color;
        cell->bg_color = vt->bg_color;
        cell->dirty = true;
    }
}

static void clear_screen(struct vt* vt) {
    for (size_t y = 0; y < vt->num_rows; ++y)
        clear_line_at(vt, 0, y, vt->num_columns);
    vt->flags |= VT_WHOLE_SCREEN_DIRTY;
}

static void write_char_at(struct vt* vt, size_t x, size_t y, char c) {
    ASSERT(x < vt->num_columns);
    ASSERT(y < vt->num_rows);

    uint8_t new_fg_color = vt->fg_color;
    uint8_t new_bg_color = vt->bg_color;
    if (vt->flags & VT_ITALIC)
        new_fg_color = ITALIC_COLOR;
    else if (vt->flags & VT_UNDERLINE)
        new_fg_color = UNDERLINE_COLOR;
    else if (vt->intensity == VT_INTENSITY_FAINT)
        new_fg_color = FAINT_COLOR;
    if (vt->flags & VT_COLOR_REVERSED) {
        // Swap colors but keep the COLOR_BRIGHT bit unchanged.
        uint8_t fg = new_fg_color;
        uint8_t bg = new_bg_color;
        new_fg_color = (fg & COLOR_BRIGHT) | (bg & ~COLOR_BRIGHT);
        new_bg_color = (bg & COLOR_BRIGHT) | (fg & ~COLOR_BRIGHT);
    }
    if (vt->flags & VT_BLINK)
        new_bg_color ^= COLOR_BRIGHT;
    if (vt->intensity == VT_INTENSITY_BOLD)
        new_fg_color ^= COLOR_BRIGHT;

    struct cell* cell = vt->cells + x + y * vt->num_columns;
    if (cell->ch == c && cell->fg_color == new_fg_color &&
        cell->bg_color == new_bg_color)
        return;

    cell->ch = c;
    cell->fg_color = new_fg_color;
    cell->bg_color = new_bg_color;
    cell->dirty = true;
}

static void advance_to_next_line(struct vt* vt) {
    if (vt->cursor_y + 1 < vt->num_rows) {
        set_cursor(vt, 0, vt->cursor_y + 1);
        return;
    }

    // Scroll up by one line
    const struct cell* src = vt->cells + vt->num_columns;
    struct cell* dst = vt->cells;
    for (size_t i = 0; i < vt->num_columns * (vt->num_rows - 1); ++i) {
        if (dst->ch != src->ch || dst->fg_color != src->fg_color ||
            dst->bg_color != src->bg_color) {
            *dst = *src;
            dst->dirty = true;
        }
        ++src;
        ++dst;
    }
    clear_line_at(vt, 0, vt->num_rows - 1, vt->num_columns);
    set_cursor(vt, 0, vt->num_rows - 1);
}

void vt_flush(struct vt* vt) {
    struct screen* screen = vt->screen;

    if ((vt->flags & VT_PALETTE_DIRTY) && screen->set_palette) {
        // If the palette is changed, we need to redraw the whole screen
        vt->flags |= VT_WHOLE_SCREEN_DIRTY;

        screen->set_palette(vt->palette);
    }

    if ((vt->flags & VT_FONT_DIRTY) && screen->set_font) {
        // If the font is changed, we need to redraw the whole screen
        vt->flags |= VT_WHOLE_SCREEN_DIRTY;

        screen->set_font(vt->font);
    }

    if (vt->flags & VT_WHOLE_SCREEN_DIRTY) {
        // Ensures to clear not only the portion covered by the cells
        // but also the margin area.
        // VT_COLOR_REVERSED doesn't affect clearing.
        screen->clear(vt->bg_color);
    }

    if ((vt->flags & VT_CURSOR_DIRTY) && screen->set_cursor)
        screen->set_cursor(vt->cursor_x, vt->cursor_y,
                           vt->flags & VT_CURSOR_VISIBLE);

    struct cell* cell = vt->cells;
    for (size_t y = 0; y < vt->num_rows; ++y) {
        for (size_t x = 0; x < vt->num_columns; ++x, ++cell) {
            if (cell->dirty || (vt->flags & VT_WHOLE_SCREEN_DIRTY)) {
                screen->put(x, y, cell->ch, cell->fg_color, cell->bg_color);
                cell->dirty = false;
            }
        }
    }

    vt->flags &= ~VT_ALL_DIRTY;
}

void vt_set_palette(struct vt* vt, const uint32_t palette[NUM_COLORS]) {
    memcpy(vt->palette, palette, sizeof(vt->palette));
    vt->flags |= VT_PALETTE_DIRTY;
}

struct font* vt_get_font(const struct vt* vt) {
    return vt->font ? font_ref(vt->font) : NULL;
}

struct font* vt_swap_font(struct vt* vt, struct font* font) {
    struct font* old_font = vt->font;
    vt->font = font ? font_ref(font) : NULL;
    vt->flags |= VT_FONT_DIRTY;
    return old_font;
}

void vt_invalidate_all(struct vt* vt) { vt->flags |= VT_ALL_DIRTY; }

static void reset_params(struct vt* vt) {
    vt->num_params = 0;
    memset(vt->params, 0, sizeof(vt->params));
}

NODISCARD static enum state handle_ground(struct vt* vt, char c) {
    switch (c) {
    case '\x1b':
        return STATE_ESC;
    case '\r':
        set_cursor(vt, 0, vt->cursor_y);
        break;
    case '\n':
    case '\v':
    case '\f':
        advance_to_next_line(vt);
        break;
    case '\b':
        if (vt->cursor_x > 0)
            set_cursor(vt, vt->cursor_x - 1, vt->cursor_y);
        break;
    case '\t':
        if (vt->cursor_x + 1 < vt->num_columns) {
            size_t x = vt->cursor_x + 1;
            x = ROUND_UP(x, TAB_STOP);
            x = MIN(x, vt->num_columns - 1);
            set_cursor(vt, x, vt->cursor_y);
        }
        break;
    default:
        if (!isascii(c))
            return STATE_GROUND;
        if (vt->flags & VT_STOMP)
            advance_to_next_line(vt);
        write_char_at(vt, vt->cursor_x, vt->cursor_y, c);
        if (vt->cursor_x + 1 < vt->num_columns) {
            set_cursor(vt, vt->cursor_x + 1, vt->cursor_y);
        } else {
            // Even if we reach the end of the line, we don't immediately
            // advance to the next line until the next character is printed.
            vt->flags |= VT_STOMP;
        }
        break;
    }
    return STATE_GROUND;
}

NODISCARD static enum state handle_state_esc(struct vt* vt, char c) {
    switch (c) {
    case '[':
        reset_params(vt);
        return STATE_CSI;
    case ']':
        return STATE_OSC;
    }
    vt->state = STATE_GROUND;
    return handle_ground(vt, c);
}

// Cursor Up
static void handle_csi_cuu(struct vt* vt) {
    unsigned dy = vt->params[0];
    if (dy == 0)
        dy = 1;
    if (dy > vt->cursor_y)
        set_cursor(vt, vt->cursor_x, 0);
    else
        set_cursor(vt, vt->cursor_x, vt->cursor_y - dy);
}

// Cursor Down
static void handle_csi_cud(struct vt* vt) {
    unsigned dy = vt->params[0];
    if (dy == 0)
        dy = 1;
    if (dy + vt->cursor_y >= vt->num_rows)
        set_cursor(vt, vt->cursor_x, vt->num_rows - 1);
    else
        set_cursor(vt, vt->cursor_x, vt->cursor_y + dy);
}

// Cursor Forward
static void handle_csi_cuf(struct vt* vt) {
    unsigned dx = vt->params[0];
    if (dx == 0)
        dx = 1;
    if (dx + vt->cursor_x >= vt->num_columns)
        set_cursor(vt, vt->num_columns - 1, vt->cursor_y);
    else
        set_cursor(vt, vt->cursor_x + dx, vt->cursor_y);
}

// Cursor Back
static void handle_csi_cub(struct vt* vt) {
    unsigned dx = vt->params[0];
    if (dx == 0)
        dx = 1;
    if (dx > vt->cursor_x)
        set_cursor(vt, 0, vt->cursor_y);
    else
        set_cursor(vt, vt->cursor_x - dx, vt->cursor_y);
}

// Cursor Next Line
static void handle_csi_cnl(struct vt* vt) {
    unsigned dy = vt->params[0];
    if (dy == 0)
        dy = 1;
    if (dy + vt->cursor_y >= vt->num_rows)
        set_cursor(vt, 0, vt->num_rows - 1);
    else
        set_cursor(vt, 0, vt->cursor_y + dy);
}

// Cursor Previous Line
static void handle_csi_cpl(struct vt* vt) {
    unsigned dy = vt->params[0];
    if (dy == 0)
        dy = 1;
    if (dy > vt->cursor_y)
        set_cursor(vt, 0, 0);
    else
        set_cursor(vt, 0, vt->cursor_y - dy);
}

// Cursor Horizontal Absolute
static void handle_csi_cha(struct vt* vt) {
    unsigned x = vt->params[0];
    if (x > 0)
        --x;
    if (x >= vt->num_columns)
        x = vt->num_columns - 1;
    set_cursor(vt, x, vt->cursor_y);
}

// Cursor Position
static void handle_csi_cup(struct vt* vt) {
    size_t x = vt->params[1];
    size_t y = vt->params[0];
    if (x > 0)
        --x;
    if (y > 0)
        --y;
    if (x >= vt->num_columns)
        x = vt->num_columns - 1;
    if (y >= vt->num_rows)
        y = vt->num_rows - 1;
    set_cursor(vt, x, y);
}

// Erase in Display
static void handle_csi_ed(struct vt* vt) {
    switch (vt->params[0]) {
    case 0:
        clear_line_at(vt, vt->cursor_x, vt->cursor_y,
                      vt->num_columns - vt->cursor_x);
        for (size_t y = vt->cursor_y + 1; y < vt->num_rows; ++y)
            clear_line_at(vt, 0, y, vt->num_columns);
        break;
    case 1:
        if (vt->cursor_y > 0) {
            for (size_t y = 0; y < vt->cursor_y; ++y)
                clear_line_at(vt, 0, y, vt->num_columns);
        }
        clear_line_at(vt, 0, vt->cursor_y, vt->cursor_x + 1);
        break;
    case 2:
        clear_screen(vt);
        break;
    }
}

// Erase in Line
static void handle_csi_el(struct vt* vt) {
    switch (vt->params[0]) {
    case 0:
        clear_line_at(vt, vt->cursor_x, vt->cursor_y,
                      vt->num_columns - vt->cursor_x);
        break;
    case 1:
        clear_line_at(vt, 0, vt->cursor_y, vt->cursor_x + 1);
        break;
    case 2:
        clear_line_at(vt, 0, vt->cursor_y, vt->num_columns);
        break;
    }
}

// Select Graphic Rendition
__extension__ static void handle_csi_sgr(struct vt* vt) {
    for (size_t i = 0; i < vt->num_params; ++i) {
        unsigned p = vt->params[i];
        switch (p) {
        case 0:
            vt->fg_color = DEFAULT_FG_COLOR;
            vt->bg_color = DEFAULT_BG_COLOR;
            vt->flags &=
                ~(VT_ITALIC | VT_UNDERLINE | VT_BLINK | VT_COLOR_REVERSED);
            vt->intensity = VT_INTENSITY_NORMAL;
            break;
        case 1:
            vt->intensity = VT_INTENSITY_BOLD;
            break;
        case 2:
            vt->intensity = VT_INTENSITY_FAINT;
            break;
        case 3:
            vt->flags |= VT_ITALIC;
            break;
        case 4:  // Underline
        case 21: // Double underline
            vt->flags |= VT_UNDERLINE;
            break;
        case 5:
            vt->flags |= VT_BLINK;
            break;
        case 7:
            vt->flags |= VT_COLOR_REVERSED;
            break;
        case 22:
            vt->intensity = VT_INTENSITY_NORMAL;
            break;
        case 23:
            vt->flags &= ~VT_ITALIC;
            break;
        case 24:
            vt->flags &= ~VT_UNDERLINE;
            break;
        case 25:
            vt->flags &= ~VT_BLINK;
            break;
        case 27:
            vt->flags &= ~VT_COLOR_REVERSED;
            break;
        case 30 ... 37:
            vt->fg_color = p - 30;
            break;
        case 39:
            vt->fg_color = DEFAULT_FG_COLOR;
            break;
        case 40 ... 47:
            vt->bg_color = p - 40;
            break;
        case 49:
            vt->bg_color = DEFAULT_BG_COLOR;
            break;
        case 90 ... 97:
            vt->fg_color = p - 90;
            vt->intensity = VT_INTENSITY_BOLD;
            break;
        case 100 ... 107:
            // Linux does not support bold intensity for background colors
            vt->bg_color = p - 100;
            break;
        }
    }
}

NODISCARD static bool parse_csi_param(struct vt* vt, char c) {
    if (c == ';') {
        if (vt->num_params < ARRAY_SIZE(vt->params) - 1) {
            ++vt->num_params;
            return true;
        }
    } else if (isdigit(c)) {
        unsigned* p = &vt->params[vt->num_params];
        *p = *p * 10 + (c - '0');
        return true;
    } else if (' ' <= c && c <= '?') {
        return true;
    }
    ++vt->num_params;
    return false;
}

NODISCARD static enum state handle_state_csi_ecma(struct vt* vt, char c) {
    if (parse_csi_param(vt, c))
        return STATE_CSI_ECMA;

    switch (c) {
    case 'A':
        handle_csi_cuu(vt);
        break;
    case 'B':
        handle_csi_cud(vt);
        break;
    case 'C':
        handle_csi_cuf(vt);
        break;
    case 'D':
        handle_csi_cub(vt);
        break;
    case 'E':
        handle_csi_cnl(vt);
        break;
    case 'F':
        handle_csi_cpl(vt);
        break;
    case 'G':
        handle_csi_cha(vt);
        break;
    case 'H':
        handle_csi_cup(vt);
        break;
    case 'J':
        handle_csi_ed(vt);
        break;
    case 'K':
        handle_csi_el(vt);
        break;
    case 'm':
        handle_csi_sgr(vt);
        break;
    }

    return STATE_GROUND;
}

static void handle_csi_dec_hl(struct vt* vt, bool enable) {
    for (size_t i = 0; i < vt->num_params; ++i) {
        switch (vt->params[i]) {
        case 25: // Text Cursor Enable Mode
            if (enable != (bool)(vt->flags & VT_CURSOR_VISIBLE)) {
                invalidate_cell(vt, vt->cursor_x, vt->cursor_y);
                vt->flags |= VT_CURSOR_DIRTY;
            }
            if (enable)
                vt->flags |= VT_CURSOR_VISIBLE;
            else
                vt->flags &= ~VT_CURSOR_VISIBLE;
            break;
        }
    }
}

NODISCARD static enum state handle_state_csi_dec(struct vt* vt, char c) {
    if (parse_csi_param(vt, c))
        return STATE_CSI_DEC;

    switch (c) {
    case 'h':
        handle_csi_dec_hl(vt, true);
        break;
    case 'l':
        handle_csi_dec_hl(vt, false);
        break;
    }

    return STATE_GROUND;
}

NODISCARD static enum state handle_state_csi(struct vt* vt, char c) {
    switch (c) {
    case '?':
        return STATE_CSI_DEC;
    }
    vt->state = STATE_CSI_ECMA;
    return handle_state_csi_ecma(vt, c);
}

NODISCARD static enum state handle_state_osc(struct vt* vt, char c) {
    switch (c) {
    case 'P':
        reset_params(vt);
        return STATE_OSC_PALETTE;
    }
    return STATE_GROUND;
}

static unsigned char parse_hex_digit(char c) {
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    ASSERT('a' <= c && c <= 'f');
    return c - 'a' + 10;
}

NODISCARD static enum state handle_state_osc_palette(struct vt* vt, char c) {
    if (!isxdigit(c))
        return STATE_GROUND;

    vt->params[vt->num_params++] = parse_hex_digit(c);
    if (vt->num_params < 7)
        return STATE_OSC_PALETTE;

    unsigned index = vt->params[0];
    ASSERT(index < NUM_COLORS);
    uint32_t r = (vt->params[1] << 4) | vt->params[2];
    uint32_t g = (vt->params[3] << 4) | vt->params[4];
    uint32_t b = (vt->params[5] << 4) | vt->params[6];
    uint32_t color = (r << 16) | (g << 8) | b;
    vt->palette[index] = color;
    vt->flags |= VT_PALETTE_DIRTY;
    return STATE_GROUND;
}

static void on_char(struct vt* vt, char c) {
    switch (vt->state) {
    case STATE_GROUND:
        vt->state = handle_ground(vt, c);
        return;
    case STATE_ESC:
        vt->state = handle_state_esc(vt, c);
        return;
    case STATE_CSI:
        vt->state = handle_state_csi(vt, c);
        return;
    case STATE_CSI_ECMA:
        vt->state = handle_state_csi_ecma(vt, c);
        return;
    case STATE_CSI_DEC:
        vt->state = handle_state_csi_dec(vt, c);
        return;
    case STATE_OSC:
        vt->state = handle_state_osc(vt, c);
        return;
    case STATE_OSC_PALETTE:
        vt->state = handle_state_osc_palette(vt, c);
        return;
    }
    UNREACHABLE();
}

void vt_write(struct vt* vt, const char* buf, size_t count) {
    for (size_t i = 0; i < count; ++i)
        on_char(vt, buf[i]);
}

struct vt* vt_create(struct screen* screen) {
    ASSERT_PTR(screen->get_size);
    ASSERT_PTR(screen->put);
    ASSERT_PTR(screen->clear);

    size_t num_columns;
    size_t num_rows;
    screen->get_size(&num_columns, &num_rows);

    struct vt* vt FREE(kfree) = kmalloc(sizeof(struct vt));
    if (!vt)
        return ERR_PTR(-ENOMEM);

    *vt = (struct vt){
        .screen = screen,
        .num_columns = num_columns,
        .num_rows = num_rows,
        .state = STATE_GROUND,
        .fg_color = DEFAULT_FG_COLOR,
        .bg_color = DEFAULT_BG_COLOR,
        .flags = VT_CURSOR_VISIBLE | VT_ALL_DIRTY,
    };

    vt->cells = kmalloc(num_columns * num_rows * sizeof(struct cell));
    if (!vt->cells)
        return ERR_PTR(-ENOMEM);

    for (size_t i = 0; i < num_columns * num_rows; ++i) {
        vt->cells[i] = (struct cell){
            .ch = ' ',
            .fg_color = DEFAULT_FG_COLOR,
            .bg_color = DEFAULT_BG_COLOR,
            .dirty = true,
        };
    }

    clear_screen(vt);
    vt_flush(vt);

    return TAKE_PTR(vt);
}
