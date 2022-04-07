#pragma once

#include "forward.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SERIAL_COM1 0x3f8
#define SERIAL_COM2 0x2f8
#define SERIAL_COM3 0x3e8
#define SERIAL_COM4 0x2e8

bool serial_enable_port(uint16_t port);
size_t serial_write(uint16_t port, const char* s, size_t count);
struct file* serial_device_create(uint16_t port);
