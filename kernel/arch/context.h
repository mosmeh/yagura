#pragma once

#include <arch/context.h>
#include <common/macros.h>
#include <common/stdbool.h>

struct task;
struct registers;
struct sigaction;
struct arch_task;

// Initialize architecture-specific context for a new kernel task.
NODISCARD int arch_init_task(struct task*, void (*entry_point)(void));

// Clone architecture-specific context from one task to another.
// If user_stack is non-null, the new task should use it as the user stack
// pointer.
NODISCARD int arch_clone_task(struct task* to, const struct task* from,
                              const struct registers* from_regs,
                              void* user_stack);

// Switches context from prev to next.
void arch_switch_context(struct task* prev, struct task* next);

// Enter user mode for the given task, starting execution at the specified
// entry point with the given user stack.
_Noreturn void arch_enter_user_mode(struct task*, void* entry_point,
                                    void* user_stack);

// Set the Thread-Local Storage (TLS) pointer for the given task.
NODISCARD int arch_set_tls(struct task*, void* user_tls);

// Handles a signal.
// The register state should be modified so that the signal handler is invoked
// when returning to user mode.
NODISCARD int arch_handle_signal(struct registers*, int signum,
                                 const struct sigaction*);

// Dump the register state using kmsg.
void arch_dump_registers(const struct registers*);

// Walk the stack frames starting from the given base pointer (bp).
// For each stack frame, the provided callback function must be called
// with the instruction pointer (ip) and the provided data pointer.
// If the callback returns false, the stack walk should stop.
void arch_walk_stack(uintptr_t bp, bool (*callback)(uintptr_t ip, void* data),
                     void* data);

// Returns true if the given register state shows that the CPU is in user mode.
bool arch_is_user_mode(const struct registers*);
