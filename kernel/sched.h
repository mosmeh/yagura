#pragma once

#include <common/macros.h>
#include <common/stdbool.h>

struct task;
struct registers;
struct timespec;

void sched_init_smp(void);

// Registers a task to be scheduled.
void sched_register(struct task*);

// Starts the scheduler on the current CPU.
_Noreturn void sched_start(void);

// Yields the CPU to another task.
void sched_yield(void);

// Requests rescheduling of the given task.
void sched_reschedule(struct task*);

// Should be called on every timer tick.
void sched_tick(struct registers*);

#define BLOCK_UNINTERRUPTIBLE 1

// Returns true if the task should be unblocked.
typedef bool (*unblock_fn)(void*);

// Blocks the current task until the unblock function returns true.
// If unblock is NULL, the task will never be unblocked unless interrupted.
// Returns -EINTR if the task was interrupted.
NODISCARD int sched_block(unblock_fn, void* data, int flags);

// Blocks the current task for the specified duration.
void sched_sleep(const struct timespec*);
