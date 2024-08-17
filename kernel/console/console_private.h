#pragma once

#include <kernel/api/termios.h>
#include <kernel/containers/ring_buf.h>
#include <kernel/fs/fs.h>

struct screen;

void serial_console_init(void);
void virtual_console_init(struct screen*);
void system_console_init(void);

struct attr_char {
    char ch;
    bool eol;
};

typedef void (*tty_echo_fn)(const char*, size_t, void* ctx);

struct tty {
    struct inode inode;
    struct termios termios;

    struct ring_buf input_buf;
    struct attr_char line_buf[1024];
    size_t line_len;

    tty_echo_fn echo;
    void* echo_ctx;

    pid_t pgid;
    size_t num_columns, num_rows;
};

// Initializes a tty structure in place, with the given minor device number.
NODISCARD int tty_init(struct tty*, uint8_t minor);

// Inputs the given string into the tty.
ssize_t tty_emit(struct tty*, const char* buf, size_t count);

// Sets the echo callback for the tty. The callback is called with the given
// context.
void tty_set_echo(struct tty*, tty_echo_fn, void* ctx);

// Sets the size of the tty.
void tty_set_size(struct tty*, size_t num_columns, size_t num_rows);

// Creates a virtual terminal with the given screen as the backend.
struct vt* vt_create(struct screen*);

// Inputs into the vt.
void vt_write(struct vt*, const char* buf, size_t count);

// Invalidates the entire screen, forcing a redraw on the next flush.
void vt_invalidate_all(struct vt*);

// Flushes the updates to the screen.
void vt_flush(struct vt*);
