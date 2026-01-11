#pragma once

#include <arch/interrupts.h>
#include <stdint.h>

struct registers;

typedef void (*interrupt_handler_fn)(struct registers*);
void arch_interrupts_set_handler(uint8_t num, interrupt_handler_fn handler);

bool arch_interrupts_enabled(void);
void arch_enable_interrupts(void);
void arch_disable_interrupts(void);

// Pause execution until the next interrupt.
void arch_wait_for_interrupt(void);
