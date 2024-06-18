#include "console.h"
#include "psf.h"
#include <common/extra.h>
#include <common/stdlib.h>
#include <common/string.h>
#include <kernel/api/fb.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/hid.h>
#include <kernel/api/signum.h>
#include <kernel/api/sys/ioctl.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/api/sys/types.h>
#include <kernel/drivers/graphics/graphics.h>
#include <kernel/drivers/hid/hid.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts.h>
#include <kernel/kprintf.h>
#include <kernel/lock.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/ring_buf.h>
#include <kernel/safe_string.h>
#include <kernel/scheduler.h>

#define TAB_STOP 8

#define DEFAULT_FG_COLOR 7
#define DEFAULT_BG_COLOR 0

static const uint32_t palette[] = {
    0x191919, 0xcc0000, 0x4e9a06, 0xc4a000, 0x3465a4, 0x75507b,
    0x06989a, 0xd0d0d0, 0x555753, 0xef2929, 0x8ae234, 0xfce94f,
    0x729fcf, 0xad7fa8, 0x34e2e2, 0xeeeeec,
};

struct cell {
    char ch;
    uint8_t fg_color;
    uint8_t bg_color;
};

static struct font* font;
static uintptr_t fb_addr;
static struct fb_info fb_info;
static size_t num_columns;
static size_t num_rows;
static size_t cursor_x = 0;
static size_t cursor_y = 0;
static bool is_cursor_visible = true;
static enum { STATE_GROUND, STATE_ESC, STATE_CSI } state = STATE_GROUND;
static uint8_t fg_color = DEFAULT_FG_COLOR;
static uint8_t bg_color = DEFAULT_BG_COLOR;
static struct cell* cells;
static bool* line_is_dirty;
static bool whole_screen_should_be_cleared = false;
static bool stomp = false;

static void set_cursor(size_t x, size_t y) {
    stomp = false;
    line_is_dirty[cursor_y] = true;
    line_is_dirty[y] = true;
    cursor_x = x;
    cursor_y = y;
}

static void clear_line_at(size_t x, size_t y, size_t length) {
    struct cell* cell = cells + x + y * num_columns;
    for (size_t i = 0; i < length; ++i) {
        cell->ch = ' ';
        cell->fg_color = fg_color;
        cell->bg_color = bg_color;
        ++cell;
    }
    line_is_dirty[y] = true;
}

static void clear_screen(void) {
    for (size_t y = 0; y < num_rows; ++y)
        clear_line_at(0, y, num_columns);
    whole_screen_should_be_cleared = true;
}

static void write_char_at(size_t x, size_t y, char c) {
    struct cell* cell = cells + x + y * num_columns;
    cell->ch = c;
    cell->fg_color = fg_color;
    cell->bg_color = bg_color;
    line_is_dirty[y] = true;
}

static void scroll_up(void) {
    memmove(cells, cells + num_columns,
            num_columns * (num_rows - 1) * sizeof(struct cell));
    for (size_t y = 0; y < num_rows - 1; ++y)
        line_is_dirty[y] = true;
    clear_line_at(0, num_rows - 1, num_columns);
}

static void flush_cell_at(size_t x, size_t y, struct cell* cell) {
    bool is_cursor = is_cursor_visible && x == cursor_x && y == cursor_y;
    uint32_t fg = palette[is_cursor ? cell->bg_color : cell->fg_color];
    uint32_t bg = palette[is_cursor ? cell->fg_color : cell->bg_color];

    const unsigned char* glyph =
        font->glyphs +
        font->ascii_to_glyph[(size_t)cell->ch] * font->bytes_per_glyph;
    uintptr_t row_addr = fb_addr + x * font->glyph_width * sizeof(uint32_t) +
                         y * font->glyph_height * fb_info.pitch;
    for (size_t py = 0; py < font->glyph_height; ++py) {
        uint32_t* pixel = (uint32_t*)row_addr;
        for (size_t px = 0; px < font->glyph_width; ++px) {
            uint32_t val = *(const uint32_t*)glyph;
            uint32_t swapped = ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) |
                               ((val >> 8) & 0xff00) |
                               ((val << 24) & 0xff000000);
            *pixel++ = swapped & (1 << (32 - px - 1)) ? fg : bg;
        }
        glyph += font->bytes_per_glyph / font->glyph_height;
        row_addr += fb_info.pitch;
    }
}

static void flush(void) {
    if (whole_screen_should_be_cleared) {
        memset32((uint32_t*)fb_addr, palette[bg_color],
                 fb_info.pitch * fb_info.height / sizeof(uint32_t));
        whole_screen_should_be_cleared = false;
    }

    struct cell* row_cells = cells;
    bool* dirty = line_is_dirty;
    for (size_t y = 0; y < num_rows; ++y) {
        if (*dirty) {
            struct cell* cell = row_cells;
            for (size_t x = 0; x < num_columns; ++x)
                flush_cell_at(x, y, cell++);
            *dirty = false;
        }
        row_cells += num_columns;
        ++dirty;
    }
}

static void handle_ground(char c) {
    switch (c) {
    case '\x1b':
        state = STATE_ESC;
        return;
    case '\r':
        set_cursor(0, cursor_y);
        break;
    case '\n':
        set_cursor(0, cursor_y + 1);
        break;
    case '\b':
        if (cursor_x > 0)
            set_cursor(cursor_x - 1, cursor_y);
        break;
    case '\t':
        set_cursor(round_up(cursor_x + 1, TAB_STOP), cursor_y);
        break;
    default:
        if ((unsigned)c > 127)
            return;
        if (stomp)
            set_cursor(0, cursor_y + 1);
        if (cursor_y >= num_rows) {
            scroll_up();
            set_cursor(cursor_x, num_rows - 1);
        }
        write_char_at(cursor_x, cursor_y, c);
        set_cursor(cursor_x + 1, cursor_y);
        break;
    }
    if (cursor_x >= num_columns) {
        set_cursor(num_columns - 1, cursor_y);

        // event if we reach at the right end of a screen, we don't proceed to
        // the next line until we write the next character
        stomp = true;
    }
}

static char param_buf[1024];
static size_t param_buf_idx = 0;

static void handle_state_esc(char c) {
    switch (c) {
    case '[':
        param_buf_idx = 0;
        state = STATE_CSI;
        return;
    }
    state = STATE_GROUND;
    handle_ground(c);
}

// Cursor Up
static void handle_csi_cuu(void) {
    unsigned dy = atoi(param_buf);
    if (dy == 0)
        dy = 1;
    if (dy > cursor_y)
        set_cursor(cursor_x, 0);
    else
        set_cursor(cursor_x, cursor_y - dy);
}

// Cursor Down
static void handle_csi_cud(void) {
    unsigned dy = atoi(param_buf);
    if (dy == 0)
        dy = 1;
    if (dy + cursor_y >= num_rows)
        set_cursor(cursor_x, num_rows - 1);
    else
        set_cursor(cursor_x, cursor_y + dy);
}

// Cursor Forward
static void handle_csi_cuf(void) {
    unsigned dx = atoi(param_buf);
    if (dx == 0)
        dx = 1;
    if (dx + cursor_x >= num_columns)
        set_cursor(num_columns - 1, cursor_y);
    else
        set_cursor(cursor_x + dx, cursor_y);
}

// Cursor Back
static void handle_csi_cub(void) {
    unsigned dx = atoi(param_buf);
    if (dx == 0)
        dx = 1;
    if (dx > cursor_x)
        set_cursor(0, cursor_y);
    else
        set_cursor(cursor_x - dx, cursor_y);
}

// Cursor Horizontal Absolute
static void handle_csi_cha(void) {
    unsigned x = atoi(param_buf);
    if (x > 0)
        --x;
    if (x >= num_columns)
        x = num_columns - 1;
    set_cursor(x, cursor_y);
}

// Cursor Position
static void handle_csi_cup(void) {
    size_t x = 0;
    size_t y = 0;

    static const char* sep = ";";
    char* saved_ptr;
    const char* param = strtok_r(param_buf, sep, &saved_ptr);
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

    if (x >= num_columns)
        x = num_columns - 1;
    if (y >= num_rows)
        y = num_rows - 1;
    set_cursor(x, y);
}

// Erase in Display
static void handle_csi_ed(void) {
    switch (atoi(param_buf)) {
    case 0:
        clear_line_at(cursor_x, cursor_y, num_columns - cursor_x);
        for (size_t y = cursor_y + 1; y < num_rows; ++y)
            clear_line_at(0, y, num_columns);
        break;
    case 1:
        if (cursor_y > 0) {
            for (size_t y = 0; y < cursor_y; ++y)
                clear_line_at(0, y, num_columns);
        }
        clear_line_at(0, cursor_y, cursor_x + 1);
        break;
    case 2:
        clear_screen();
        break;
    }
}

// Erase in Line
static void handle_csi_el(void) {
    switch (atoi(param_buf)) {
    case 0:
        clear_line_at(cursor_x, cursor_y, num_columns - cursor_x);
        break;
    case 1:
        clear_line_at(0, cursor_y, cursor_x + 1);
        break;
    case 2:
        clear_line_at(0, cursor_y, num_columns);
        break;
    }
}

// Select Graphic Rendition
static void handle_csi_sgr(void) {
    if (param_buf[0] == '\0') {
        fg_color = DEFAULT_FG_COLOR;
        bg_color = DEFAULT_BG_COLOR;
        return;
    }

    static const char* sep = ";";
    char* saved_ptr;
    bool bold = false;
    for (const char* param = strtok_r(param_buf, sep, &saved_ptr); param;
         param = strtok_r(NULL, sep, &saved_ptr)) {
        int num = atoi(param);
        if (num == 0) {
            fg_color = DEFAULT_FG_COLOR;
            bg_color = DEFAULT_BG_COLOR;
            bold = false;
        } else if (num == 1) {
            bold = true;
        } else if (num == 7) {
            uint8_t tmp = fg_color;
            fg_color = bg_color;
            bg_color = tmp;
        } else if (num == 22) {
            fg_color = DEFAULT_FG_COLOR;
            bold = false;
        } else if (30 <= num && num <= 37) {
            fg_color = num - 30 + (bold ? 8 : 0);
        } else if (num == 38) {
            fg_color = DEFAULT_FG_COLOR;
        } else if (40 <= num && num <= 47) {
            bg_color = num - 40 + (bold ? 8 : 0);
        } else if (num == 48) {
            bg_color = DEFAULT_BG_COLOR;
        } else if (90 <= num && num <= 97) {
            fg_color = num - 90 + 8;
        } else if (100 <= num && num <= 107) {
            bg_color = num - 100 + 8;
        }
    }
}

// Text Cursor Enable Mode
static void handle_csi_dectcem(char c) {
    if (strcmp(param_buf, "?25") != 0)
        return;
    switch (c) {
    case 'h':
        is_cursor_visible = true;
        line_is_dirty[cursor_y] = true;
        return;
    case 'l':
        is_cursor_visible = false;
        line_is_dirty[cursor_y] = true;
        return;
    }
}

static void handle_state_csi(char c) {
    if (c < 0x40) {
        param_buf[param_buf_idx++] = c;
        return;
    }
    param_buf[param_buf_idx] = '\0';

    switch (c) {
    case 'A':
        handle_csi_cuu();
        break;
    case 'B':
        handle_csi_cud();
        break;
    case 'C':
        handle_csi_cuf();
        break;
    case 'D':
        handle_csi_cub();
        break;
    case 'G':
        handle_csi_cha();
        break;
    case 'H':
        handle_csi_cup();
        break;
    case 'J':
        handle_csi_ed();
        break;
    case 'K':
        handle_csi_el();
        break;
    case 'm':
        handle_csi_sgr();
        break;
    case 'h':
    case 'l':
        handle_csi_dectcem(c);
        break;
    }

    state = STATE_GROUND;
}

static void on_char(char c) {
    switch (state) {
    case STATE_GROUND:
        handle_ground(c);
        return;
    case STATE_ESC:
        handle_state_esc(c);
        return;
    case STATE_CSI:
        handle_state_csi(c);
        return;
    }
    UNREACHABLE();
}

static ring_buf input_buf;

static void input_buf_write_str(const char* s) {
    bool int_flag = push_cli();
    ring_buf_write_evicting_oldest(&input_buf, s, strlen(s));
    pop_cli(int_flag);
}

static pid_t pgid;

static void on_key_event(const key_event* event) {
    if (!event->pressed)
        return;
    switch (event->keycode) {
    case KEYCODE_UP:
        input_buf_write_str("\x1b[A");
        return;
    case KEYCODE_DOWN:
        input_buf_write_str("\x1b[B");
        return;
    case KEYCODE_RIGHT:
        input_buf_write_str("\x1b[C");
        return;
    case KEYCODE_LEFT:
        input_buf_write_str("\x1b[D");
        return;
    case KEYCODE_HOME:
        input_buf_write_str("\x1b[H");
        return;
    case KEYCODE_END:
        input_buf_write_str("\x1b[F");
        return;
    case KEYCODE_DELETE:
        input_buf_write_str("\x1b[3~");
        return;
    default:
        break;
    }

    if (!event->key)
        return;
    char key = event->key;
    if (event->modifiers & KEY_MODIFIER_CTRL) {
        if ('a' <= key && key <= 'z')
            key -= '`';
        else if (key == '\\')
            key = 0x1c;
    }

    tty_maybe_send_signal(pgid, key);

    bool int_flag = push_cli();
    ring_buf_write_evicting_oldest(&input_buf, &key, 1);
    pop_cli(int_flag);
}

static bool can_read(void) {
    bool int_flag = push_cli();
    bool ret = !ring_buf_is_empty(&input_buf);
    pop_cli(int_flag);
    return ret;
}

static bool read_should_unblock(file_description* desc) {
    (void)desc;
    return can_read();
}

static ssize_t fb_console_device_read(file_description* desc, void* buffer,
                                      size_t count) {
    (void)desc;

    for (;;) {
        int rc = file_description_block(desc, read_should_unblock);
        if (IS_ERR(rc))
            return rc;

        bool int_flag = push_cli();
        if (ring_buf_is_empty(&input_buf)) {
            pop_cli(int_flag);
            continue;
        }

        ssize_t nread = ring_buf_read(&input_buf, buffer, count);
        pop_cli(int_flag);
        return nread;
    }
}

static mutex lock;

static ssize_t fb_console_device_write(file_description* desc,
                                       const void* buffer, size_t count) {
    (void)desc;
    const char* chars = (char*)buffer;
    mutex_lock(&lock);

    for (size_t i = 0; i < count; ++i)
        on_char(chars[i]);
    flush();

    mutex_unlock(&lock);
    return count;
}

static int fb_console_device_ioctl(file_description* desc, int request,
                                   void* user_argp) {
    (void)desc;
    switch (request) {
    case TIOCGPGRP:
        if (!copy_to_user(user_argp, &pgid, sizeof(pid_t)))
            return -EFAULT;
        return 0;
    case TIOCSPGRP: {
        pid_t new_pgid;
        if (!copy_from_user(&new_pgid, user_argp, sizeof(pid_t)))
            return -EFAULT;
        if (new_pgid < 0)
            return -EINVAL;
        pgid = new_pgid;
        return 0;
    }
    case TIOCGWINSZ: {
        struct winsize winsize = {.ws_col = num_columns,
                                  .ws_row = num_rows,
                                  .ws_xpixel = 0,
                                  .ws_ypixel = 0};
        if (!copy_to_user(user_argp, &winsize, sizeof(struct winsize)))
            return -EFAULT;
        return 0;
    }
    }
    return -EINVAL;
}

static short fb_console_device_poll(file_description* desc, short events) {
    (void)desc;
    short revents = 0;
    if ((events & POLLIN) && can_read())
        revents |= POLLIN;
    if (events & POLLOUT)
        revents |= POLLOUT;
    return revents;
}

static struct inode* fb_console_device_get(void) {
    static file_ops fops = {.read = fb_console_device_read,
                            .write = fb_console_device_write,
                            .ioctl = fb_console_device_ioctl,
                            .poll = fb_console_device_poll};
    static struct inode inode = {
        .fops = &fops, .mode = S_IFCHR, .rdev = makedev(5, 0), .ref_count = 1};
    return &inode;
}

void fb_console_init(void) {
    if (!fb_get())
        return;

    font = load_psf("/usr/share/fonts/ter-u16n.psf");
    ASSERT_OK(font);

    ASSERT_OK(fb_get()->get_info(&fb_info));
    ASSERT(fb_info.bpp == 32);

    num_columns = fb_info.width / font->glyph_width;
    num_rows = fb_info.height / font->glyph_height;
    kprintf("fb_console: columns=%u rows=%u\n", num_columns, num_rows);

    cells = kmalloc(num_columns * num_rows * sizeof(struct cell));
    ASSERT(cells);
    line_is_dirty = kmalloc(num_rows * sizeof(bool));
    ASSERT(line_is_dirty);

    size_t fb_size = fb_info.pitch * fb_info.height;
    fb_addr = range_allocator_alloc(&kernel_vaddr_allocator, fb_size);
    ASSERT_OK(fb_addr);
    ASSERT_OK(fb_get()->mmap(fb_addr, fb_size, 0,
                             PAGE_WRITE | PAGE_SHARED | PAGE_GLOBAL));

    clear_screen();
    flush();

    ASSERT_OK(ring_buf_init(&input_buf));
    ps2_set_key_event_handler(on_key_event);

    ASSERT_OK(vfs_register_device(fb_console_device_get()));
}
