#pragma once

#include "forward.h"
#include <stdint.h>

#define SERIAL_COM1 0x3f8
#define SERIAL_COM2 0x2f8
#define SERIAL_COM3 0x3e8
#define SERIAL_COM4 0x2e8

void serial_init(void);
void serial_write(uint16_t port, char c);
fs_node* serial_device_create(uint16_t port);
