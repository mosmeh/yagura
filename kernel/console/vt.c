#include "console_private.h"
#include <common/stdlib.h>
#include <common/string.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

#define TAB_STOP 8

#define DEFAULT_FG_COLOR 15
#define DEFAULT_BG_COLOR 0
#define VGA_BRIGHT 8

static uint8_t TO_VGA_COLOR[] = {
    0, // black
    4, // read
    2, // green
    6, // brown
    1, // blue
    5, // magenta
    3, // cyan
    7, // light gray
};

struct cell {
    char ch;
    uint8_t fg_color;
    uint8_t bg_color;
};

struct vt {
    struct screen* screen;

    size_t num_columns;
    size_t num_rows;

    size_t cursor_x;
    size_t cursor_y;
    bool is_cursor_visible;

    enum { STATE_GROUND, STATE_ESC, STATE_CSI } state;
    bool stomp;
    char param_buf[1024];
    size_t param_buf_index;

    uint8_t fg_color;
    uint8_t bg_color;

    struct cell* cells;
    bool* line_is_dirty;
    bool clear_on_flush;
};

static void set_cursor(struct vt* vt, size_t x, size_t y) {
    vt->stomp = false;
    vt->line_is_dirty[vt->cursor_y] = true;
    vt->line_is_dirty[y] = true;
    vt->cursor_x = x;
    vt->cursor_y = y;
    vt->screen->set_cursor(vt->screen, x, y, vt->is_cursor_visible);
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
    vt->clear_on_flush = true;
}

static void write_char_at(struct vt* vt, size_t x, size_t y, char c) {
    struct cell* cell = vt->cells + x + y * vt->num_columns;
    cell->ch = c;
    cell->fg_color = vt->fg_color;
    cell->bg_color = vt->bg_color;
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
    if (vt->clear_on_flush) {
        vt->screen->clear(vt->screen, vt->bg_color);
        vt->clear_on_flush = false;
    }

    struct cell* row_cells = vt->cells;
    bool* dirty = vt->line_is_dirty;
    for (size_t y = 0; y < vt->num_rows; ++y) {
        if (*dirty) {
            struct cell* cell = row_cells;
            for (size_t x = 0; x < vt->num_columns; ++x) {
                vt->screen->put(vt->screen, x, y, cell->ch, cell->fg_color,
                                cell->bg_color);
                ++cell;
            }
            *dirty = false;
        }
        row_cells += vt->num_columns;
        ++dirty;
    }
}

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
        set_cursor(vt, round_up(vt->cursor_x + 1, TAB_STOP), vt->cursor_y);
        break;
    default:
        if ((unsigned)c > 127)
            return;
        if (vt->stomp)
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

        // event if we reach at the right end of a screen, we don't proceed to
        // the next line until we write the next character
        vt->stomp = true;
    }
}

static void handle_state_esc(struct vt* vt, char c) {
    switch (c) {
    case '[':
        vt->param_buf_index = 0;
        vt->state = STATE_CSI;
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

    static const char* sep = ";";
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

    static const char* sep = ";";
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
            uint8_t tmp = vt->fg_color;
            vt->fg_color = vt->bg_color;
            vt->bg_color = tmp;
        } else if (num == 22) {
            vt->fg_color = DEFAULT_FG_COLOR;
            bold = false;
        } else if (30 <= num && num <= 37) {
            vt->fg_color = TO_VGA_COLOR[num - 30] | (bold ? VGA_BRIGHT : 0);
        } else if (num == 38) {
            vt->fg_color = DEFAULT_FG_COLOR;
        } else if (40 <= num && num <= 47) {
            vt->bg_color = TO_VGA_COLOR[num - 40] | (bold ? VGA_BRIGHT : 0);
        } else if (num == 48) {
            vt->bg_color = DEFAULT_BG_COLOR;
        } else if (90 <= num && num <= 97) {
            vt->fg_color = TO_VGA_COLOR[num - 90] | VGA_BRIGHT;
        } else if (100 <= num && num <= 107) {
            vt->bg_color = TO_VGA_COLOR[num - 100] | VGA_BRIGHT;
        }
    }
}

// Text Cursor Enable Mode
static void handle_csi_dectcem(struct vt* vt, char c) {
    if (strcmp(vt->param_buf, "?25") != 0)
        return;
    switch (c) {
    case 'h':
        vt->is_cursor_visible = true;
        break;
    case 'l':
        vt->is_cursor_visible = false;
        break;
    default:
        return;
    }
    vt->line_is_dirty[vt->cursor_y] = true;
    vt->screen->set_cursor(vt->screen, vt->cursor_x, vt->cursor_y,
                           vt->is_cursor_visible);
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

void vt_on_char(struct vt* vt, char c) {
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
    }
    UNREACHABLE();
}

struct vt* vt_create(struct screen* screen) {
    size_t num_columns;
    size_t num_rows;
    screen->get_size(screen, &num_columns, &num_rows);

    struct vt* vt = kmalloc(sizeof(struct vt));
    if (!vt)
        return NULL;

    *vt = (struct vt){
        .screen = screen,
        .num_columns = num_columns,
        .num_rows = num_rows,
        .is_cursor_visible = true,
        .state = STATE_GROUND,
        .fg_color = DEFAULT_FG_COLOR,
        .bg_color = DEFAULT_BG_COLOR,
    };

    vt->cells = kmalloc(num_columns * num_rows * sizeof(struct cell));
    if (!vt->cells)
        goto fail;
    vt->line_is_dirty = kmalloc(num_rows * sizeof(bool));
    if (!vt->line_is_dirty)
        goto fail;

    clear_screen(vt);
    vt_flush(vt);

    return vt;

fail:
    kfree(vt->line_is_dirty);
    kfree(vt->cells);
    kfree(vt);
    return NULL;
}
