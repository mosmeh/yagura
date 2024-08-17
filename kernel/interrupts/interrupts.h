#pragma once

#include <kernel/asm_wrapper.h>
#include <kernel/panic.h>

struct registers;

#define IRQ(i) (0x20 + (i))
#define NUM_IRQS 16
#define LAPIC_TIMER_VECTOR 0x82
#define IPI_VECTOR 0x83
#define LAPIC_ERROR_VECTOR 0x84
#define SPURIOUS_VECTOR 0xff

void idt_init(void);
void idt_set_gate_user_callable(uint8_t index);
void idt_flush(void);

void i8259_init(void);
void i8259_disable(void);
void i8259_eoi(uint8_t irq);

typedef void (*interrupt_handler_fn)(struct registers*);
void idt_set_interrupt_handler(uint8_t num, interrupt_handler_fn handler);

void lapic_init(void);
void lapic_init_cpu(void);

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

static inline bool interrupts_enabled(void) { return read_eflags() & 0x200; }

static inline bool push_cli(void) {
    bool enabled = interrupts_enabled();
    cli();
    return enabled;
}

static inline void pop_cli(bool was_enabled) {
    ASSERT(!interrupts_enabled());
    if (was_enabled)
        sti();
}

void do_iret(struct registers);
