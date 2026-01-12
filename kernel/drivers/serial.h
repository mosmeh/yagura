#pragma once

#include <common/stdbool.h>
#include <common/stddef.h>
#include <common/stdint.h>

#define SERIAL_NUM_PORTS 4

void serial_early_init(void);
bool serial_is_port_enabled(uint8_t index);
void serial_write(uint8_t index, const char* s, size_t count);
void serial_set_input_handler(void (*handler)(uint8_t index, char));
