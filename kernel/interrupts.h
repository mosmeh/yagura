#pragma once

#include <kernel/arch/interrupts.h>
#include <kernel/panic.h>

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

static inline void __interrupts_restorer_leave(void* p) {
    struct __interrupts_restorer* guard = p;
    bool current_state = arch_interrupts_enabled();
    ASSERT(current_state == guard->expected_state);
    if (current_state == guard->previous_state)
        return;
    if (guard->previous_state)
        arch_enable_interrupts();
    else
        arch_disable_interrupts();
}
