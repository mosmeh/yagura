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
void vt_on_char(struct vt*, char);
void vt_flush(struct vt*);
