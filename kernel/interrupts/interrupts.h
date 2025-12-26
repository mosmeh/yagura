#pragma once

#include <kernel/api/asm/processor-flags.h>
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

static inline bool interrupts_enabled(void) {
    return read_eflags() & X86_EFLAGS_IF;
}

static inline void enable_interrupts(void) { __asm__ volatile("sti"); }

static inline void disable_interrupts(void) { __asm__ volatile("cli"); }

#define SCOPED_ENABLE_INTERRUPTS()                                             \
    __RESTORE_INTERRUPTS_ON_LEAVE(true);                                       \
    enable_interrupts();

#define SCOPED_DISABLE_INTERRUPTS()                                            \
    __RESTORE_INTERRUPTS_ON_LEAVE(false);                                      \
    disable_interrupts();

struct __interrupts_restorer {
    bool previous_state;
    bool expected_state;
};

#define __RESTORE_INTERRUPTS_ON_LEAVE(new_state)                               \
    struct __interrupts_restorer CONCAT(__interrupts_restorer, __COUNTER__)    \
        CLEANUP(__interrupts_restorer_leave) = {                               \
            .previous_state = interrupts_enabled(),                            \
            .expected_state = (new_state),                                     \
    };

static inline void __interrupts_restorer_leave(void* p) {
    struct __interrupts_restorer* guard = p;
    bool current_state = interrupts_enabled();
    ASSERT(current_state == guard->expected_state);
    if (current_state == guard->previous_state)
        return;
    if (guard->previous_state)
        enable_interrupts();
    else
        disable_interrupts();
}

void do_iret(struct registers);
