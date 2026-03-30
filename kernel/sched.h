#pragma once

#include <common/macros.h>
#include <common/stdbool.h>

struct task;
struct registers;
struct file;
struct vec;

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

// Returns true if the task should be unblocked.
typedef bool (*wake_fn)(void* ctx);

struct wait_state {
    wake_fn wake;
    void* ctx;
    bool interrupted;
};

// Blocks the current task until the wake function returns true.
// If wake function is NULL, the task will be blocked forever.
void sched_wait(wake_fn, void* ctx);

// Same as `sched_wait()` except that the task will not contribute to
// load average while waiting.
void sched_wait_as_idle(wake_fn, void* ctx);

// Same as `sched_wait()` except that it can be interrupted by signals.
// Returns -EINTR if interrupted by a signal.
NODISCARD int sched_wait_interruptible(wake_fn, void* ctx);

// Gets the 1, 5, and 15 minute load averages in the format used by
// the `loads` field of `struct sysinfo`.
void sched_get_loads(unsigned long out_loads[3]);

int proc_print_loadavg(struct file*, struct vec*);
