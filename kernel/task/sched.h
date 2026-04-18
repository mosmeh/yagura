#pragma once

#include <common/macros.h>
#include <common/stdbool.h>
#include <kernel/interrupts.h>
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
// int wait(struct file* file) {
//     if (!condition) {
//         if (file->flags & O_NONBLOCK)
//             return -EAGAIN;
//         WAIT(&wq, condition);
//         // Or, if the wait should be interruptible:
//         // if (WAIT_INTERRUPTIBLE(&wq, condition))
//         //     return -EINTR;
//     }
//     return 0;
// }

#define WAIT(wq, condition)                                                    \
    do {                                                                       \
        ASSERT(arch_interrupts_enabled());                                     \
        if (!(condition)) {                                                    \
            for (;;) {                                                         \
                SCOPED_WAIT(waiter, wq);                                       \
                if (condition)                                                 \
                    break;                                                     \
                waiter_wait(&waiter);                                          \
            }                                                                  \
        }                                                                      \
    } while (0)

#define WAIT_AS_IDLE(wq, condition)                                            \
    do {                                                                       \
        ASSERT(arch_interrupts_enabled());                                     \
        if (!(condition)) {                                                    \
            for (;;) {                                                         \
                SCOPED_WAIT(waiter, wq);                                       \
                if (condition)                                                 \
                    break;                                                     \
                waiter_wait_as_idle(&waiter);                                  \
            }                                                                  \
        }                                                                      \
    } while (0)

#define WAIT_INTERRUPTIBLE(wq, condition)                                      \
    __extension__({                                                            \
        ASSERT(arch_interrupts_enabled());                                     \
        int __rc = 0;                                                          \
        if (!(condition)) {                                                    \
            for (;;) {                                                         \
                SCOPED_WAIT(waiter, wq);                                       \
                if (condition)                                                 \
                    break;                                                     \
                __rc = waiter_wait_interruptible(&waiter);                     \
                if (__rc)                                                      \
                    break;                                                     \
            }                                                                  \
        }                                                                      \
        __rc;                                                                  \
    })

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

#define SCOPED_WAIT(name, wq)                                                  \
    struct waiter name CLEANUP(__waiter_deinit);                               \
    __waiter_init(&(name), wq)

struct waiter {
    struct waitqueue* wq;
    struct task* task;
    struct waiter* prev;
    struct waiter* next;
    bool published;
};

void __waiter_init(struct waiter*, struct waitqueue*);
void __waiter_deinit(struct waiter*);

// Wakes up a waiter and removes it from the waitqueue.
// Returns true if the waiter was removed from the waitqueue,
// false if the waiter was not enqueued or already removed.
NODISCARD bool waiter_wake(struct waiter*);

// Sleeps until the waiter is woken up.
void waiter_wait(struct waiter*);

// Like `waiter_wait` but does not contribute to load average while waiting.
void waiter_wait_as_idle(struct waiter*);

// Like `waiter_wait` but returns -EINTR if interrupted by a signal.
NODISCARD int waiter_wait_interruptible(struct waiter*);

// Gets the 1, 5, and 15 minute load averages in the format used by
// the `loads` field of `struct sysinfo`.
void sched_get_loads(unsigned long out_loads[3]);

int proc_print_loadavg(struct file*, struct vec*);
