#pragma once

#include "forward.h"
#include <stdbool.h>
#include <stdint.h>

#define SERIAL_COM1 0x3f8
#define SERIAL_COM2 0x2f8
#define SERIAL_COM3 0x3e8
#define SERIAL_COM4 0x2e8

bool serial_enable_port(uint16_t port);
void serial_write(uint16_t port, char c);
struct file* serial_device_create(uint16_t port);
