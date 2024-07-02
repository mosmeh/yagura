#pragma once

#include <stdint.h>

void console_init(void);

void serial_console_on_char(uint16_t port, char);
