#pragma once

#include <arch/io.h>

uint8_t in8(uint16_t port);
uint16_t in16(uint16_t port);
uint32_t in32(uint16_t port);
void out8(uint16_t port, uint8_t data);
void out16(uint16_t port, uint16_t data);
void out32(uint16_t port, uint32_t data);

// Delay for at least the specified number of microseconds.
void delay(unsigned long usec);
