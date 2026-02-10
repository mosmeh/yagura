#pragma once

#include <kernel/api/termios.h>
#include <kernel/console/screen/screen.h>
#include <kernel/containers/ring_buf.h>
#include <kernel/device/device.h>
#include <kernel/fs/fs.h>

struct screen;
struct tty;

void serial_console_init(void);
void virtual_console_init(struct screen*);
void system_console_init(void);

struct attr_char {
    char ch;
    bool eol;
};

struct tty_ops {
    void (*echo)(struct tty*, const char* buf, size_t size);
    int (*ioctl)(struct tty*, struct file*, unsigned cmd, unsigned long arg);
};

struct ktermios {
    tcflag_t c_iflag;      // input mode flags
    tcflag_t c_oflag;      // output mode flags
    tcflag_t c_cflag;      // control mode flags
    tcflag_t c_lflag;      // local mode flags
    cc_t c_line;           // line discipline
    cc_t c_cc[LINUX_NCCS]; // control characters
    speed_t c_ispeed;      // input speed
    speed_t c_ospeed;      // output speed
};

STATIC_ASSERT(sizeof(struct ktermios) == sizeof(struct linux_termios2));
STATIC_ASSERT(sizeof(struct linux_termios) < sizeof(struct linux_termios2));

struct tty {
    struct char_dev char_dev;
    char name[16];
    dev_t dev;
    const struct tty_ops* ops;
    size_t num_columns;
    size_t num_rows;

    struct ktermios termios;

    struct ring_buf* input_buf;
    struct attr_char line_buf[1024];
    size_t line_len;

    pid_t pgid;

    struct spinlock lock;
};

DEFINE_LOCKED(tty, struct tty*, spinlock, lock)

extern const struct file_ops tty_fops;

NODISCARD int tty_register(struct tty*);

// Inputs the given string into the tty.
ssize_t tty_emit(struct tty*, const char* buf, size_t count);

// Creates a virtual terminal with the given screen as the backend.
struct vt* vt_create(struct screen*);

// Inputs into the vt.
// Writes to the backing screen will be deferred until vt_flush is called.
void vt_write(struct vt*, const char* buf, size_t count);

// Sets the color palette for the vt.
// The palette should be an array of 32-bit RGB values corresponding to
// the ANSI color codes.
void vt_set_palette(struct vt*, const uint32_t[NUM_COLORS]);

// Gets the current font used by the vt.
// Returns NULL if no font is set.
NODISCARD struct font* vt_get_font(struct vt*);

// Sets the font used by the vt, returning the previous font.
// Returns NULL if no font was previously set.
NODISCARD struct font* vt_swap_font(struct vt*, struct font*);

// Invalidates the entire screen, forcing a redraw on the next flush.
void vt_invalidate_all(struct vt*);

// Flushes the updates to the screen.
void vt_flush(struct vt*);
