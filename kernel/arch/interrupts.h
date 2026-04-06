#pragma once

#include <arch/interrupts.h>

bool arch_interrupts_enabled(void);
void arch_enable_interrupts(void);
void arch_disable_interrupts(void);

// Pause execution until the next interrupt.
void arch_wait_for_interrupt(void);
