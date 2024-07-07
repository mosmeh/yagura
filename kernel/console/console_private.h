#pragma once

#include "screen/screen.h"
#include <kernel/api/sys/types.h>
#include <stdbool.h>
#include <stddef.h>

void serial_console_init(void);
void virtual_console_init(struct screen*);
void system_console_init(void);

void tty_maybe_send_signal(pid_t pgid, char ch);

struct vt* vt_create(struct screen*);

// Inputs into the vt.
void vt_write(struct vt*, const char* buf, size_t count);

// Invalidates the entire screen, forcing a redraw on the next flush.
void vt_invalidate_all(struct vt*);

// Flushes the updates to the screen.
void vt_flush(struct vt*);
