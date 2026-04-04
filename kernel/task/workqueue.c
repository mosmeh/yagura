#include <common/stdatomic.h>
#include <kernel/api/err.h>
#include <kernel/panic.h>
#include <kernel/task/sched.h>
#include <kernel/task/workqueue.h>
#include <kernel/time.h>

static struct workqueue __global_workqueue;
struct workqueue* global_workqueue = &__global_workqueue;

void workqueue_submit_delayed(struct workqueue* wq, struct work* work,
                              work_fn func, const struct timespec* delay) {
    ASSERT_PTR(work);
    ASSERT_PTR(func);

    // work->func != NULL indicates that the work is already pending.
    work_fn expected_func = NULL;
    ASSERT(atomic_compare_exchange_strong(&work->func, &expected_func, func));

    struct timespec deadline;
    ASSERT_OK(time_now(CLOCK_MONOTONIC, &deadline));
    if (delay)
        timespec_add(&deadline, delay);

    *work = (struct work){
        .func = func,
        .deadline = deadline,
    };

    SCOPED_LOCK(spinlock, &wq->lock);
    struct tree_node** new_node = &wq->works.root;
    struct tree_node* parent = NULL;
    while (*new_node) {
        parent = *new_node;
        struct work* w = CONTAINER_OF(parent, struct work, tree_node);
        if (timespec_compare(&work->deadline, &w->deadline) < 0) {
            new_node = &parent->left;
        } else {
            // If the deadlines are the same, the new work will be executed
            // after the existing one (FIFO order).
            new_node = &parent->right;
        }
    }
    *new_node = &work->tree_node;
    tree_insert(&wq->works, parent, *new_node);
}

static bool wake_dispatch(void* ctx) {
    struct workqueue* wq = ctx;

    SCOPED_LOCK(spinlock, &wq->lock);

    struct tree_node* node = tree_first(&wq->works);
    if (!node)
        return false;

    struct work* work = CONTAINER_OF(node, struct work, tree_node);

    struct timespec now;
    ASSERT_OK(time_now(CLOCK_MONOTONIC, &now));
    return timespec_compare(&now, &work->deadline) >= 0;
}

NODISCARD static bool execute_one(struct workqueue* wq) {
    struct timespec now;
    ASSERT_OK(time_now(CLOCK_MONOTONIC, &now));

    struct work* work = NULL;
    {
        SCOPED_LOCK(spinlock, &wq->lock);
        struct tree_node* node = tree_first(&wq->works);
        if (!node)
            return false;
        work = CONTAINER_OF(node, struct work, tree_node);
        if (timespec_compare(&now, &work->deadline) < 0)
            return false;
        tree_remove(&wq->works, node);
    }

    work_fn func = work->func;
    ASSERT_PTR(func);

    // Mark the work as not pending.
    // This must be done before executing the work to allow re-submitting the
    // work from the func.
    work->func = NULL;

    func(work);
    return true;
}

void workqueue_dispatch(struct workqueue* wq) {
    for (;;) {
        bool executed = false;
        while (execute_one(wq))
            executed = true;
        if (executed)
            return;
        sched_wait_as_idle(wake_dispatch, wq);
    }
}
