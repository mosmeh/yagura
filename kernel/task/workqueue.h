#pragma once

#include <kernel/lock.h>
#include <kernel/panic.h>
#include <kernel/task/sched.h>

struct workqueue {
    struct work* head;
    struct work* tail;
    struct waitqueue wait;
    struct spinlock lock;
};

extern struct workqueue* global_workqueue;

struct work;

typedef void (*work_fn)(struct work*);

struct work {
    _Atomic(work_fn) func;
    struct work* next;
};

// Submits a work to the workqueue.
void workqueue_submit(struct workqueue*, struct work*, work_fn);

// If `immediate` is true, executes the work immediately in the current context.
// Otherwise, submits the work to the workqueue.
static inline void workqueue_submit_or_execute(struct workqueue* wq,
                                               struct work* work, work_fn func,
                                               bool immediate) {
    ASSERT_PTR(work);
    ASSERT(!work->func);
    if (immediate)
        func(work);
    else
        workqueue_submit(wq, work, func);
}

// Executes at least one work that is ready. If there are no ready works,
// waits until the next work is ready and executes it.
void workqueue_dispatch(struct workqueue*);
