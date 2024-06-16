#pragma once

#include <kernel/api/sys/types.h>

void console_init(void);

void serial_console_on_char(uint16_t port, char);

void tty_maybe_send_signal(pid_t pgid, char ch);
