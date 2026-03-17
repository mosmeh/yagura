#pragma once

#include <common/stddef.h>

void console_init(void);

// Sends the given string to the system console's output.
void system_console_echo(const char* buf, size_t count);
