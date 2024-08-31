#pragma once

#include <common/extra.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdnoreturn.h>

struct task;
struct registers;

void scheduler_init(void);

// Registers a task to be scheduled.
void scheduler_register(struct task*);

// Starts the scheduler on the current CPU.
noreturn void scheduler_start(void);

// Yields the current CPU to other tasks.
void scheduler_yield(bool requeue_current);

// Should be called on every timer tick.
void scheduler_tick(struct registers*);

#define BLOCK_UNINTERRUPTIBLE 1

// Returns true if the task should be unblocked.
typedef bool (*unblock_fn)(void*);

// Blocks the current task until the unblock function returns true.
// Returns -EINTR if the task was interrupted.
NODISCARD int scheduler_block(unblock_fn, void* data, int flags);
