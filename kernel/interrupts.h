#pragma once

#include <kernel/arch/interrupts.h>
#include <kernel/panic.h>

struct registers;

#define SCOPED_ENABLE_INTERRUPTS()                                             \
    __RESTORE_INTERRUPTS_ON_LEAVE(true);                                       \
    arch_enable_interrupts();

#define SCOPED_DISABLE_INTERRUPTS()                                            \
    __RESTORE_INTERRUPTS_ON_LEAVE(false);                                      \
    arch_disable_interrupts();

struct __interrupts_restorer {
    bool previous_state;
    bool expected_state;
};

#define __RESTORE_INTERRUPTS_ON_LEAVE(new_state)                               \
    struct __interrupts_restorer CONCAT(__interrupts_restorer, __COUNTER__)    \
        CLEANUP(__interrupts_restorer_leave) = {                               \
            .previous_state = arch_interrupts_enabled(),                       \
            .expected_state = (new_state),                                     \
    };

static inline void
__interrupts_restorer_leave(const struct __interrupts_restorer* guard) {
    bool current_state = arch_interrupts_enabled();
    ASSERT(current_state == guard->expected_state);
    if (current_state == guard->previous_state)
        return;
    if (guard->previous_state)
        arch_enable_interrupts();
    else
        arch_disable_interrupts();
}

typedef void (*interrupt_handler_fn)(struct registers*, void* ctx);

// Registers an interrupt handler for the given interrupt number.
// Returns true if the handler was successfully registered, or false if
// the same (num, fn, ctx) triple was already registered.
// Panics if called after enabling SMP.
bool interrupt_register(uint8_t num, interrupt_handler_fn, void* ctx);

// Unregisters an interrupt handler with the given (num, fn, ctx) triple.
// Returns true if the handler was successfully unregistered, or false if
// no such handler was registered.
// Panics if called after enabling SMP.
bool interrupt_unregister(uint8_t num, interrupt_handler_fn, void* ctx);

// Called from the architecture-specific interrupt handler to dispatch the
// interrupt to the registered handlers.
// Returns true if the interrupt was handled by at least one handler, or false
// if no handlers were registered for the interrupt.
bool interrupt_handle(uint8_t num, struct registers*);
