#include "psf.h"
#include <common/extra.h>
#include <common/stdlib.h>
#include <common/string.h>
#include <kernel/api/fb.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/hid.h>
#include <kernel/api/mman.h>
#include <kernel/api/stat.h>
#include <kernel/api/sysmacros.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts.h>
#include <kernel/kmalloc.h>
#include <kernel/lock.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/scheduler.h>
#include <string.h>

#define TAB_STOP 8

#define DEFAULT_FG_COLOR 0xd0d0d0
#define DEFAULT_BG_COLOR 0x191919

static const uint32_t palette[] = {
    DEFAULT_BG_COLOR, 0xcc0000,         0x4e9a06, 0xc4a000, 0x3465a4, 0x75507b,
    0x06989a,         DEFAULT_FG_COLOR, 0x555753, 0xef2929, 0x8ae234, 0xfce94f,
    0x729fcf,         0xad7fa8,         0x34e2e2, 0xeeeeec,
};

static struct font* font;
static uintptr_t fb_addr;
static struct fb_info fb_info;
static size_t console_width;
static size_t console_height;
static size_t console_x = 0;
static size_t console_y = 0;
static enum { STATE_GROUND, STATE_ESC, STATE_CSI } state = STATE_GROUND;
static uint32_t fg_color = DEFAULT_FG_COLOR;
static uint32_t bg_color = DEFAULT_BG_COLOR;

static void clear_line_at(size_t x, size_t y, size_t length) {
    uintptr_t row_addr = fb_addr + x * font->glyph_width * sizeof(uint32_t) +
                         y * font->glyph_height * fb_info.pitch;
    for (size_t y = 0; y < font->glyph_height; ++y) {
        memset32((uint32_t*)row_addr, bg_color, length * font->glyph_width);
        row_addr += fb_info.pitch;
    }
}

static void clear_screen(void) {
    memset32((void*)fb_addr, bg_color,
             fb_info.pitch * fb_info.height / sizeof(uint32_t));
}

static void write_char_at(size_t x, size_t y, char c) {
    const unsigned char* glyph =
        font->glyphs + font->ascii_to_glyph[(size_t)c] * font->bytes_per_glyph;
    uintptr_t row_addr = fb_addr + x * font->glyph_width * sizeof(uint32_t) +
                         y * font->glyph_height * fb_info.pitch;
    for (size_t py = 0; py < font->glyph_height; ++py) {
        uint32_t* pixel = (uint32_t*)row_addr;
        for (size_t px = 0; px < font->glyph_width; ++px) {
            uint32_t val = *(const uint32_t*)glyph;
            uint32_t swapped = ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) |
                               ((val >> 8) & 0xff00) |
                               ((val << 24) & 0xff000000);
            *pixel++ = swapped & (1 << (32 - px - 1)) ? fg_color : bg_color;
        }
        glyph += font->bytes_per_glyph / font->glyph_height;
        row_addr += fb_info.pitch;
    }
}

static void handle_ground(char c) {
    switch (c) {
    case '\x1b':
        state = STATE_ESC;
        return;
    case '\r':
        console_x = 0;
        break;
    case '\n':
        console_x = 0;
        ++console_y;
        break;
    case '\b':
        if (console_x > 0)
            --console_x;
        break;
    case '\t':
        console_x = round_up(console_x + 1, TAB_STOP);
        break;
    default:
        if ((unsigned)c > 127)
            return;
        write_char_at(console_x, console_y, c);
        ++console_x;
        break;
    }
    if (console_x >= console_width) {
        console_x = 0;
        ++console_y;
    }
    if (console_y >= console_height) {
        memmove((void*)fb_addr,
                (void*)(fb_addr + fb_info.pitch * font->glyph_height),
                fb_info.pitch * (console_height - 1) * font->glyph_height);
        clear_line_at(0, console_height - 1, console_width);
        --console_y;
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
            x = atoi(param) - 1;
            break;
        case 1:
            y = atoi(param) - 1;
            break;
        }
        param = strtok_r(NULL, sep, &saved_ptr);
    }

    console_x = x;
    console_y = y;
}

// Erase in Display
static void handle_csi_ed() {
    switch (atoi(param_buf)) {
    case 0:
        clear_line_at(console_x, console_y, console_width - console_x);
        for (size_t y = console_y + 1; y < console_height; ++y)
            clear_line_at(0, y, console_width);
        break;
    case 1:
        if (console_y > 0) {
            for (size_t y = 0; y < console_y - 1; ++y)
                clear_line_at(0, y, console_width);
        }
        clear_line_at(0, console_y, console_x + 1);
        break;
    case 2:
        clear_screen();
        break;
    }
}

// Erase in Line
static void handle_csi_el() {
    switch (atoi(param_buf)) {
    case 0:
        clear_line_at(console_x, console_y, console_width - console_x);
        break;
    case 1:
        clear_line_at(0, console_y, console_x + 1);
        break;
    case 2:
        clear_line_at(0, console_y, console_width);
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
            uint32_t tmp = fg_color;
            fg_color = bg_color;
            bg_color = tmp;
        } else if (num == 22) {
            fg_color = DEFAULT_FG_COLOR;
            bold = false;
        } else if (30 <= num && num <= 37) {
            fg_color = palette[num - 30 + (bold ? 8 : 0)];
        } else if (num == 38) {
            fg_color = DEFAULT_FG_COLOR;
        } else if (40 <= num && num <= 47) {
            bg_color = palette[num - 40 + (bold ? 8 : 0)];
        } else if (num == 48) {
            bg_color = DEFAULT_BG_COLOR;
        } else if (90 <= num && num <= 97) {
            fg_color = palette[num - 90 + 8];
        } else if (100 <= num && num <= 107) {
            bg_color = palette[num - 100 + 8];
        }
    }
}

static void handle_state_csi(char c) {
    if (c < 0x40) {
        param_buf[param_buf_idx++] = c;
        return;
    }
    param_buf[param_buf_idx] = '\0';

    switch (c) {
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

static bool initialized = false;

void tty_init(void) {
    font = load_psf("/usr/share/fonts/ter-u16n.psf");
    ASSERT_OK(font);

    file_description* desc = vfs_open("/dev/fb0", O_RDWR, 0);
    ASSERT_OK(desc);

    ASSERT_OK(fs_ioctl(desc, FBIOGET_INFO, &fb_info));
    ASSERT(fb_info.bpp == 32);

    console_width = fb_info.width / font->glyph_width;
    console_height = fb_info.height / font->glyph_height;

    size_t fb_size = fb_info.pitch * fb_info.height;
    uintptr_t vaddr = memory_alloc_kernel_virtual_addr_range(fb_size);
    ASSERT_OK(vaddr);
    fb_addr = fs_mmap(desc, vaddr, fb_size, PROT_READ | PROT_WRITE, 0, true);
    ASSERT_OK(fb_addr);

    ASSERT_OK(fs_close(desc));

    clear_screen();

    initialized = true;
}

#define QUEUE_SIZE 1024

static char queue[QUEUE_SIZE];
static size_t queue_read_idx = 0;
static size_t queue_write_idx = 0;

void tty_on_key(const key_event* event) {
    if (event->pressed && event->key &&
        !(event->modifiers & ~KEY_MODIFIER_SHIFT)) {
        queue[queue_write_idx] = event->key;
        queue_write_idx = (queue_write_idx + 1) % QUEUE_SIZE;
    }
}

typedef struct tty_device {
    struct file base_file;
    mutex lock;
} tty_device;

static bool read_should_unblock(void) {
    bool int_flag = push_cli();
    bool should_unblock = queue_read_idx != queue_write_idx;
    pop_cli(int_flag);
    return should_unblock;
}

static ssize_t tty_device_read(file_description* desc, void* buffer,
                               size_t count) {
    (void)desc;

    size_t nread = 0;
    char* out = (char*)buffer;
    scheduler_block(read_should_unblock, NULL);

    bool int_flag = push_cli();

    while (count > 0) {
        if (queue_read_idx == queue_write_idx)
            break;
        *out++ = queue[queue_read_idx];
        ++nread;
        --count;
        queue_read_idx = (queue_read_idx + 1) % QUEUE_SIZE;
    }

    pop_cli(int_flag);

    return nread;
}

static ssize_t tty_device_write(file_description* desc, const void* buffer,
                                size_t count) {
    tty_device* dev = (tty_device*)desc->file;
    const char* chars = (char*)buffer;

    mutex_lock(&dev->lock);

    for (size_t i = 0; i < count; ++i)
        on_char(chars[i]);

    mutex_unlock(&dev->lock);
    return count;
}

struct file* tty_device_create(void) {
    tty_device* dev = kmalloc(sizeof(tty_device));
    if (!dev)
        return ERR_PTR(-ENOMEM);
    *dev = (tty_device){0};
    mutex_init(&dev->lock);

    struct file* file = (struct file*)dev;
    file->name = kstrdup("tty_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);
    file->mode = S_IFCHR;
    file->read = tty_device_read;
    file->write = tty_device_write;
    file->device_id = makedev(5, 0);
    return file;
}
