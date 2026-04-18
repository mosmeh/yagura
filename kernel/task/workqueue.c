#include <common/stdatomic.h>
#include <kernel/panic.h>
#include <kernel/task/sched.h>
#include <kernel/task/workqueue.h>

static struct workqueue __global_workqueue;
struct workqueue* global_workqueue = &__global_workqueue;

void workqueue_submit(struct workqueue* wq, struct work* work, work_fn func) {
    ASSERT_PTR(work);
    ASSERT_PTR(func);

    // work->func != NULL indicates that the work is already pending.
    work_fn expected_func = NULL;
    ASSERT(atomic_compare_exchange_strong(&work->func, &expected_func, func));

    *work = (struct work){.func = func};

    {
        SCOPED_LOCK(spinlock, &wq->lock);
        if (wq->tail)
            wq->tail->next = work;
        else
            wq->head = work;
        wq->tail = work;
    }

    waitqueue_wake_one(&wq->wait);
}

NODISCARD static bool execute_one(struct workqueue* wq) {
    struct work* work = NULL;
    {
        SCOPED_LOCK(spinlock, &wq->lock);
        work = wq->head;
        if (!work)
            return false;
        wq->head = work->next;
        if (!wq->head)
            wq->tail = NULL;
    }

    work_fn func = work->func;
    ASSERT_PTR(func);

    // Mark the work as not pending.
    // This must be done before executing the work to allow re-submitting the
    // work from the func.
    *work = (struct work){0};

    func(work);
    return true;
}

NODISCARD static bool execute_all(struct workqueue* wq) {
    bool executed = false;
    while (execute_one(wq))
        executed = true;
    return executed;
}

void workqueue_dispatch(struct workqueue* wq) {
    WAIT_AS_IDLE(&wq->wait, execute_all(wq));
}
