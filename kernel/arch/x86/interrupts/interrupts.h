#pragma once

#include <common/stdint.h>

void idt_init(void);
void idt_set_gate_user_callable(uint8_t index);
void idt_flush(void);

#define NUM_IRQS 16

void i8259_init(void);
void i8259_disable(void);
void i8259_eoi(uint8_t irq);

void pit_init(void);

void lapic_init(void);
void lapic_init_cpu(void);

#define LAPIC_TIMER_VECTOR 0x82
#define IPI_VECTOR 0x83
#define LAPIC_ERROR_VECTOR 0x84
#define SPURIOUS_VECTOR 0xff

uint8_t lapic_get_id(void);
void lapic_eoi(void);

#define LAPIC_ICRLO_INIT 0x00000500    // INIT/RESET
#define LAPIC_ICRLO_STARTUP 0x00000600 // Startup IPI
#define LAPIC_ICRLO_LOGICAL 0x00000800 // Destination mode
#define LAPIC_ICRLO_DELIVS 0x00001000  // Delivery status
#define LAPIC_ICRLO_ASSERT 0x00004000  // Assert interrupt (vs deassert)
#define LAPIC_ICRLO_DEASSERT 0x00000000
#define LAPIC_ICRLO_LEVEL 0x00008000 // Level triggered
#define LAPIC_ICRLO_ALL_INCL_SELF                                              \
    0x00080000 // Send to all APICs, including self.
#define LAPIC_ICRLO_ALL_EXCL_SELF                                              \
    0x000c0000 // Send to all APICs, excluding self.

void lapic_write_icr(uint32_t hi, uint32_t lo);
void lapic_broadcast_ipi(void);
void lapic_unicast_ipi(uint8_t apic_id);

void io_apic_init(void);
