#pragma once

#include <common/extra.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdnoreturn.h>

struct cpu;
struct process;
struct registers;

extern atomic_uint idle_ticks;

void scheduler_init(void);

// Registers a process to be scheduled.
void scheduler_register(struct process*);

// Starts the scheduler on the current CPU.
noreturn void scheduler_start(void);

// Yields the current CPU to other processes.
void scheduler_yield(bool requeue_current);

// Should be called on every timer tick.
void scheduler_tick(struct registers*);

#define BLOCK_UNINTERRUPTIBLE 1

// Returns true if the process should be unblocked.
typedef bool (*unblock_fn)(void*);

// Blocks the current process until the unblock function returns true.
// Returns -EINTR if the process was interrupted.
NODISCARD int scheduler_block(unblock_fn, void* data, int flags);
