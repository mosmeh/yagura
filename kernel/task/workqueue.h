#pragma once

#include <common/tree.h>
#include <kernel/api/sys/types.h>
#include <kernel/api/time.h>
#include <kernel/lock.h>
#include <kernel/panic.h>

struct workqueue {
    struct tree works;
    struct spinlock lock;
};

extern struct workqueue* global_wq;

struct work;

typedef void (*work_fn)(struct work*);

struct work {
    _Atomic(work_fn) func;
    struct timespec deadline;
    struct tree_node tree_node;
};

// Submits a work to the workqueue to be executed after the given delay.
void workqueue_submit_delayed(struct workqueue*, struct work*, work_fn,
                              const struct timespec* delay);

// Submits a work to the workqueue.
static inline void workqueue_submit(struct workqueue* wq, struct work* work,
                                    work_fn func) {
    workqueue_submit_delayed(wq, work, func, NULL);
}

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
