#pragma once

#include <common/macros.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdnoreturn.h>

struct task;
struct registers;
struct timespec;

void sched_init(void);

// Registers a task to be scheduled.
void sched_register(struct task*);

// Starts the scheduler on the current CPU.
noreturn void sched_start(void);

// Yields the current CPU to other tasks.
void sched_yield(bool requeue_current);

// Should be called on every timer tick.
void sched_tick(struct registers*);

#define BLOCK_UNINTERRUPTIBLE 1

// Returns true if the task should be unblocked.
typedef bool (*unblock_fn)(void*);

// Blocks the current task until the unblock function returns true.
// Returns -EINTR if the task was interrupted.
NODISCARD int sched_block(unblock_fn, void* data, int flags);

// Blocks the current task for the specified duration.
void sched_sleep(const struct timespec*);
