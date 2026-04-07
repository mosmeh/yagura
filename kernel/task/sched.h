#pragma once

#include <common/macros.h>
#include <common/stdbool.h>
#include <kernel/lock/spinlock.h>

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

// Wakes up a task that is sleeping.
void sched_wake(struct task*);

// Example usage of waitqueues:
//
// bool condition = false;
// struct waitqueue wq = {0};
//
// void wake(void) {
//     condition = true;
//     waitqueue_wake_all(&wq);
// }
//
// void wait(void) {
//     SCOPED_WAIT(waiter, &wq);
//     while (!condition) {
//         if (file->flags & O_NONBLOCK)
//            return -EAGAIN;
//
//         sched_wait(&waiter);
//
//         // Or, if the wait should be interruptible:
//         // if (sched_wait_interruptible(&waiter))
//         //    return -EINTR;
//     }
//     // waiter is removed from the waitqueue when going out of scope
// }

#define SCOPED_WAIT(name, waitqueue)                                           \
    struct waiter name CLEANUP(__waiter_deinit) = {.wq = (waitqueue)};

struct waiter {
    struct waitqueue* wq;
    struct task* task;
    struct waiter* prev;
    struct waiter* next;
    bool published;
};

void __waiter_deinit(struct waiter*);

struct waitqueue {
    struct waiter* head;
    struct waiter* tail;
    struct spinlock lock;
};

// Wakes at most `n` tasks waiting on the given waitqueue.
// Returns the number of tasks that were woken up.
size_t waitqueue_wake_n(struct waitqueue*, size_t n);

// Wakes at most one task waiting on the given waitqueue.
// Returns true if a task was woken up.
static inline bool waitqueue_wake_one(struct waitqueue* wq) {
    return waitqueue_wake_n(wq, 1) > 0;
}

// Wakes all tasks waiting on the given waitqueue.
// Returns the number of tasks that were woken up.
size_t waitqueue_wake_all(struct waitqueue*);

// Sleeps until the waiter is woken up.
void sched_wait(struct waiter*);

// Like `sched_wait` but does not contribute to load average while waiting.
void sched_wait_as_idle(struct waiter*);

// Like `sched_wait` but returns -EINTR if the wait was interrupted by a signal.
NODISCARD int sched_wait_interruptible(struct waiter*);

// Gets the 1, 5, and 15 minute load averages in the format used by
// the `loads` field of `struct sysinfo`.
void sched_get_loads(unsigned long out_loads[3]);

int proc_print_loadavg(struct file*, struct vec*);
