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
#define BRIGHTEN_COLOR 0x8

struct cell {
    char ch;
    uint8_t fg_color;
    uint8_t bg_color;
};

#define VT_STOMP 0x1
#define VT_CURSOR_VISIBLE 0x2
#define VT_COLOR_REVERSED 0x4

#define VT_WHOLE_SCREEN_DIRTY 0x100
#define VT_CURSOR_DIRTY 0x200
#define VT_PALETTE_DIRTY 0x400
#define VT_FONT_DIRTY 0x800

#define VT_ALL_DIRTY                                                           \
    (VT_WHOLE_SCREEN_DIRTY | VT_CURSOR_DIRTY | VT_PALETTE_DIRTY | VT_FONT_DIRTY)

struct vt {
    struct screen* screen;

    size_t num_columns;
    size_t num_rows;

    size_t cursor_x;
    size_t cursor_y;

    enum {
        STATE_GROUND,
        STATE_ESC,
        STATE_CSI,
        STATE_OSC,
        STATE_OSC_PALETTE,
    } state;
    char param_buf[1024];
    size_t param_buf_index;

    uint32_t palette[NUM_COLORS];
    uint8_t fg_color;
    uint8_t bg_color;

    struct font* font;

    struct cell* cells;
    bool* line_is_dirty;

    unsigned flags;
};

static void set_cursor(struct vt* vt, size_t x, size_t y) {
    vt->line_is_dirty[vt->cursor_y] = true;
    vt->line_is_dirty[y] = true;
    vt->cursor_x = x;
    vt->cursor_y = y;
    vt->flags &= ~VT_STOMP;
    vt->flags |= VT_CURSOR_DIRTY;
}

static void clear_line_at(struct vt* vt, size_t x, size_t y, size_t length) {
    struct cell* cell = vt->cells + x + y * vt->num_columns;
    for (size_t i = 0; i < length; ++i) {
        cell->ch = ' ';
        cell->fg_color = vt->fg_color;
        cell->bg_color = vt->bg_color;
        ++cell;
    }
    vt->line_is_dirty[y] = true;
}

static void clear_screen(struct vt* vt) {
    for (size_t y = 0; y < vt->num_rows; ++y)
        clear_line_at(vt, 0, y, vt->num_columns);
    vt->flags |= VT_WHOLE_SCREEN_DIRTY;
}

static void write_char_at(struct vt* vt, size_t x, size_t y, char c) {
    struct cell* cell = vt->cells + x + y * vt->num_columns;
    cell->ch = c;
    cell->fg_color =
        (vt->flags & VT_COLOR_REVERSED) ? vt->bg_color : vt->fg_color;
    cell->bg_color =
        (vt->flags & VT_COLOR_REVERSED) ? vt->fg_color : vt->bg_color;
    vt->line_is_dirty[y] = true;
}

static void scroll_up(struct vt* vt) {
    memmove(vt->cells, vt->cells + vt->num_columns,
            vt->num_columns * (vt->num_rows - 1) * sizeof(struct cell));
    for (size_t y = 0; y < vt->num_rows - 1; ++y)
        vt->line_is_dirty[y] = true;
    clear_line_at(vt, 0, vt->num_rows - 1, vt->num_columns);
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
        screen->clear(vt->bg_color);
    }

    if ((vt->flags & VT_CURSOR_DIRTY) && screen->set_cursor)
        screen->set_cursor(vt->cursor_x, vt->cursor_y,
                           vt->flags & VT_CURSOR_VISIBLE);

    struct cell* row_cells = vt->cells;
    bool* dirty = vt->line_is_dirty;
    for (size_t y = 0; y < vt->num_rows; ++y) {
        if (*dirty || (vt->flags & VT_WHOLE_SCREEN_DIRTY)) {
            struct cell* cell = row_cells;
            for (size_t x = 0; x < vt->num_columns; ++x) {
                screen->put(x, y, cell->ch, cell->fg_color, cell->bg_color);
                ++cell;
            }
            *dirty = false;
        }
        row_cells += vt->num_columns;
        ++dirty;
    }

    vt->flags &= ~VT_ALL_DIRTY;
}

void vt_set_palette(struct vt* vt, const uint32_t palette[NUM_COLORS]) {
    memcpy(vt->palette, palette, sizeof(vt->palette));
    vt->flags |= VT_PALETTE_DIRTY;
}

struct font* vt_get_font(struct vt* vt) {
    return vt->font ? font_ref(vt->font) : NULL;
}

struct font* vt_swap_font(struct vt* vt, struct font* font) {
    struct font* old_font = vt->font;
    vt->font = font ? font_ref(font) : NULL;
    vt->flags |= VT_FONT_DIRTY;
    return old_font;
}

void vt_invalidate_all(struct vt* vt) { vt->flags |= VT_ALL_DIRTY; }

static void handle_ground(struct vt* vt, char c) {
    switch (c) {
    case '\x1b':
        vt->state = STATE_ESC;
        return;
    case '\r':
        set_cursor(vt, 0, vt->cursor_y);
        break;
    case '\n':
        set_cursor(vt, 0, vt->cursor_y + 1);
        if (vt->cursor_y >= vt->num_rows) {
            scroll_up(vt);
            set_cursor(vt, vt->cursor_x, vt->num_rows - 1);
        }
        break;
    case '\b':
        if (vt->cursor_x > 0)
            set_cursor(vt, vt->cursor_x - 1, vt->cursor_y);
        break;
    case '\t':
        set_cursor(vt, ROUND_UP(vt->cursor_x + 1, TAB_STOP), vt->cursor_y);
        break;
    default:
        if ((unsigned)c > 127)
            return;
        if (vt->flags & VT_STOMP)
            set_cursor(vt, 0, vt->cursor_y + 1);
        if (vt->cursor_y >= vt->num_rows) {
            scroll_up(vt);
            set_cursor(vt, vt->cursor_x, vt->num_rows - 1);
        }
        write_char_at(vt, vt->cursor_x, vt->cursor_y, c);
        set_cursor(vt, vt->cursor_x + 1, vt->cursor_y);
        break;
    }
    if (vt->cursor_x >= vt->num_columns) {
        set_cursor(vt, vt->num_columns - 1, vt->cursor_y);

        // even if we reach at the right end of a screen, we don't proceed to
        // the next line until we write the next character
        vt->flags |= VT_STOMP;
    }
}

static void handle_state_esc(struct vt* vt, char c) {
    switch (c) {
    case '[':
        vt->param_buf_index = 0;
        vt->state = STATE_CSI;
        return;
    case ']':
        vt->param_buf_index = 0;
        vt->state = STATE_OSC;
        return;
    }
    vt->state = STATE_GROUND;
    handle_ground(vt, c);
}

// Cursor Up
static void handle_csi_cuu(struct vt* vt) {
    unsigned dy = atoi(vt->param_buf);
    if (dy == 0)
        dy = 1;
    if (dy > vt->cursor_y)
        set_cursor(vt, vt->cursor_x, 0);
    else
        set_cursor(vt, vt->cursor_x, vt->cursor_y - dy);
}

// Cursor Down
static void handle_csi_cud(struct vt* vt) {
    unsigned dy = atoi(vt->param_buf);
    if (dy == 0)
        dy = 1;
    if (dy + vt->cursor_y >= vt->num_rows)
        set_cursor(vt, vt->cursor_x, vt->num_rows - 1);
    else
        set_cursor(vt, vt->cursor_x, vt->cursor_y + dy);
}

// Cursor Forward
static void handle_csi_cuf(struct vt* vt) {
    unsigned dx = atoi(vt->param_buf);
    if (dx == 0)
        dx = 1;
    if (dx + vt->cursor_x >= vt->num_columns)
        set_cursor(vt, vt->num_columns - 1, vt->cursor_y);
    else
        set_cursor(vt, vt->cursor_x + dx, vt->cursor_y);
}

// Cursor Back
static void handle_csi_cub(struct vt* vt) {
    unsigned dx = atoi(vt->param_buf);
    if (dx == 0)
        dx = 1;
    if (dx > vt->cursor_x)
        set_cursor(vt, 0, vt->cursor_y);
    else
        set_cursor(vt, vt->cursor_x - dx, vt->cursor_y);
}

// Cursor Next Line
static void handle_csi_cnl(struct vt* vt) {
    unsigned dy = atoi(vt->param_buf);
    if (dy == 0)
        dy = 1;
    if (dy + vt->cursor_y >= vt->num_rows)
        set_cursor(vt, 0, vt->num_rows - 1);
    else
        set_cursor(vt, 0, vt->cursor_y + dy);
}

// Cursor Previous Line
static void handle_csi_cpl(struct vt* vt) {
    unsigned dy = atoi(vt->param_buf);
    if (dy == 0)
        dy = 1;
    if (dy > vt->cursor_y)
        set_cursor(vt, 0, 0);
    else
        set_cursor(vt, 0, vt->cursor_y - dy);
}

// Cursor Horizontal Absolute
static void handle_csi_cha(struct vt* vt) {
    unsigned x = atoi(vt->param_buf);
    if (x > 0)
        --x;
    if (x >= vt->num_columns)
        x = vt->num_columns - 1;
    set_cursor(vt, x, vt->cursor_y);
}

// Cursor Position
static void handle_csi_cup(struct vt* vt) {
    size_t x = 0;
    size_t y = 0;

    static const char* const sep = ";";
    char* saved_ptr;
    const char* param = strtok_r(vt->param_buf, sep, &saved_ptr);
    for (size_t i = 0; param; ++i) {
        switch (i) {
        case 0:
            y = atoi(param);
            if (y > 0)
                --y;
            break;
        case 1:
            x = atoi(param);
            if (x > 0)
                --x;
            break;
        }
        param = strtok_r(NULL, sep, &saved_ptr);
    }

    if (x >= vt->num_columns)
        x = vt->num_columns - 1;
    if (y >= vt->num_rows)
        y = vt->num_rows - 1;
    set_cursor(vt, x, y);
}

// Erase in Display
static void handle_csi_ed(struct vt* vt) {
    switch (atoi(vt->param_buf)) {
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
    switch (atoi(vt->param_buf)) {
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
static void handle_csi_sgr(struct vt* vt) {
    if (vt->param_buf[0] == '\0') {
        vt->fg_color = DEFAULT_FG_COLOR;
        vt->bg_color = DEFAULT_BG_COLOR;
        return;
    }

    static const char* const sep = ";";
    char* saved_ptr;
    bool bold = false;
    for (const char* param = strtok_r(vt->param_buf, sep, &saved_ptr); param;
         param = strtok_r(NULL, sep, &saved_ptr)) {
        int num = atoi(param);
        if (num == 0) {
            vt->fg_color = DEFAULT_FG_COLOR;
            vt->bg_color = DEFAULT_BG_COLOR;
            bold = false;
        } else if (num == 1) {
            bold = true;
        } else if (num == 7) {
            vt->flags |= VT_COLOR_REVERSED;
        } else if (num == 22) {
            bold = false;
        } else if (num == 27) {
            vt->flags &= ~VT_COLOR_REVERSED;
        } else if (30 <= num && num <= 37) {
            vt->fg_color = (num - 30) | (bold ? BRIGHTEN_COLOR : 0);
        } else if (num == 39) {
            vt->fg_color = DEFAULT_FG_COLOR;
        } else if (40 <= num && num <= 47) {
            vt->bg_color = (num - 40) | (bold ? BRIGHTEN_COLOR : 0);
        } else if (num == 49) {
            vt->bg_color = DEFAULT_BG_COLOR;
        } else if (90 <= num && num <= 97) {
            vt->fg_color = (num - 90) | BRIGHTEN_COLOR;
        } else if (100 <= num && num <= 107) {
            vt->bg_color = (num - 100) | BRIGHTEN_COLOR;
        }
    }
}

// Text Cursor Enable Mode
static void handle_csi_dectcem(struct vt* vt, char c) {
    if (strcmp(vt->param_buf, "?25") != 0)
        return;
    switch (c) {
    case 'h':
        vt->flags |= VT_CURSOR_VISIBLE;
        break;
    case 'l':
        vt->flags &= ~VT_CURSOR_VISIBLE;
        break;
    default:
        return;
    }
    vt->line_is_dirty[vt->cursor_y] = true;
    vt->flags |= VT_CURSOR_DIRTY;
}

static void handle_state_csi(struct vt* vt, char c) {
    if (c < 0x40) {
        vt->param_buf[vt->param_buf_index++] = c;
        return;
    }
    vt->param_buf[vt->param_buf_index] = '\0';

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
    case 'h':
    case 'l':
        handle_csi_dectcem(vt, c);
        break;
    }

    vt->state = STATE_GROUND;
}

static void handle_state_osc(struct vt* vt, char c) {
    switch (c) {
    case 'P':
        vt->param_buf_index = 0;
        vt->state = STATE_OSC_PALETTE;
        return;
    }
    vt->state = STATE_GROUND;
}

static unsigned char parse_hex_digit(char c) {
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    ASSERT('a' <= c && c <= 'f');
    return c - 'a' + 10;
}

static void handle_state_osc_palette(struct vt* vt, char c) {
    if (!isxdigit(c)) {
        vt->state = STATE_GROUND;
        return;
    }
    vt->param_buf[vt->param_buf_index++] = c;
    if (vt->param_buf_index < 7)
        return;
    unsigned char index = parse_hex_digit(vt->param_buf[0]);
    uint32_t r = (parse_hex_digit(vt->param_buf[1]) << 4) |
                 parse_hex_digit(vt->param_buf[2]);
    uint32_t g = (parse_hex_digit(vt->param_buf[3]) << 4) |
                 parse_hex_digit(vt->param_buf[4]);
    uint32_t b = (parse_hex_digit(vt->param_buf[5]) << 4) |
                 parse_hex_digit(vt->param_buf[6]);
    uint32_t color = (r << 16) | (g << 8) | b;
    vt->palette[index] = color;
    vt->flags |= VT_PALETTE_DIRTY;
    vt->state = STATE_GROUND;
}

static void on_char(struct vt* vt, char c) {
    switch (vt->state) {
    case STATE_GROUND:
        handle_ground(vt, c);
        return;
    case STATE_ESC:
        handle_state_esc(vt, c);
        return;
    case STATE_CSI:
        handle_state_csi(vt, c);
        return;
    case STATE_OSC:
        handle_state_osc(vt, c);
        return;
    case STATE_OSC_PALETTE:
        handle_state_osc_palette(vt, c);
        return;
    }
    UNREACHABLE();
}

void vt_write(struct vt* vt, const char* buf, size_t count) {
    for (size_t i = 0; i < count; ++i)
        on_char(vt, buf[i]);
}

struct vt* vt_create(struct screen* screen) {
    ASSERT(screen->get_size);
    ASSERT(screen->put);
    ASSERT(screen->clear);

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

    struct cell* cells FREE(kfree) =
        kmalloc(num_columns * num_rows * sizeof(struct cell));
    if (!cells)
        return ERR_PTR(-ENOMEM);
    bool* line_is_dirty FREE(kfree) = kmalloc(num_rows * sizeof(bool));
    if (!line_is_dirty)
        return ERR_PTR(-ENOMEM);

    vt->cells = TAKE_PTR(cells);
    vt->line_is_dirty = TAKE_PTR(line_is_dirty);

    clear_screen(vt);
    vt_flush(vt);

    return TAKE_PTR(vt);
}
