#pragma once

#include <kernel/api/termios.h>
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

struct tty {
    struct char_dev char_dev;
    char name[16];
    dev_t dev;
    const struct tty_ops* ops;
    size_t num_columns;
    size_t num_rows;

    struct termios termios;

    struct ring_buf input_buf;
    struct attr_char line_buf[1024];
    size_t line_len;

    pid_t pgid;

    struct spinlock lock;
};

extern const struct file_ops tty_fops;

NODISCARD int tty_register(struct tty*);

// Inputs the given string into the tty.
ssize_t tty_emit(struct tty*, const char* buf, size_t count);

// Creates a virtual terminal with the given screen as the backend.
struct vt* vt_create(struct screen*);

// Inputs into the vt.
// Writes to the backing screen will be deferred until vt_flush is called.
void vt_write(struct vt*, const char* buf, size_t count);

// Invalidates the entire screen, forcing a redraw on the next flush.
void vt_invalidate_all(struct vt*);

// Flushes the updates to the screen.
void vt_flush(struct vt*);
