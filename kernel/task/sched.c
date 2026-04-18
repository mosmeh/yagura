#include <common/stdio.h>
#include <common/string.h>
#include <kernel/api/sys/sysinfo.h>
#include <kernel/containers/vec.h>
#include <kernel/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>
#include <kernel/system.h>
#include <kernel/task/sched.h>
#include <kernel/task/signal.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

static _Noreturn void do_idle(void) {
    for (;;) {
        ASSERT(arch_interrupts_enabled());
        arch_wait_for_interrupt();
        sched_yield();
    }
}

void sched_init_smp(void) {
    for (size_t i = 0; i < num_cpus; ++i) {
        struct cpu* cpu = cpus[i];
        if (cpu->idle_task) {
            // BSP already has an idle task
            continue;
        }
        char comm[SIZEOF_FIELD(struct task, comm)];
        ASSERT((size_t)snprintf(comm, sizeof(comm), "idle/%zu", i) <
               sizeof(comm));
        cpu->idle_task = ASSERT_PTR(task_create(comm, do_idle));
    }
}

static struct ready_queue {
    _Atomic(struct task*) head;
    struct task* tail;
    struct spinlock lock;
} ready_queue;

DEFINE_LOCKED(ready_queue, struct ready_queue, spinlock, lock)

static void enqueue_ready(struct task* task) {
    ASSERT_PTR(task);
    ASSERT(task->state == TASK_RUNNING);
    ASSERT(!task->cpu);
    ASSERT(!task->next);
    task_ref(task);

    SCOPED_LOCK(ready_queue, &ready_queue);
    if (ready_queue.tail) {
        ready_queue.tail->next = task;
        ready_queue.tail = task;
    } else {
        ready_queue.head = ready_queue.tail = task;
    }
}

static struct task* dequeue_ready(void) {
    SCOPED_LOCK(ready_queue, &ready_queue);
    struct task* task = ready_queue.head;
    if (!task)
        return NULL;
    ASSERT(task->state == TASK_RUNNING);
    ready_queue.head = task->next;
    if (!ready_queue.head)
        ready_queue.tail = NULL;
    task->next = NULL;
    return task;
}

void sched_register(struct task* task) {
    ASSERT_PTR(task);
    ASSERT(task->state == TASK_RUNNING);
    ++task->thread_group->num_running_tasks;

    {
        SCOPED_LOCK(spinlock, &tasks_lock);
        struct tree_node** new_node = &tasks.root;
        struct tree_node* parent = NULL;
        while (*new_node) {
            parent = *new_node;
            struct task* t = CONTAINER_OF(parent, struct task, tree_node);
            if (task->tid < t->tid)
                new_node = &parent->left;
            else if (task->tid > t->tid)
                new_node = &parent->right;
            else
                PANIC("Duplicate tid");
        }
        *new_node = &task->tree_node;
        task_ref(task);
        tree_insert(&tasks, parent, *new_node);
    }

    enqueue_ready(task);
}

void sched_start(void) {
    arch_disable_interrupts();
    struct cpu* cpu = cpu_get_current();
    struct task* idle_task;
    if (cpu->current_task) {
        // Turn this task into the idle task for this CPU.
        idle_task = cpu->idle_task = cpu->current_task;
    } else if (cpu->idle_task) {
        // No current task. Run the idle task.
        idle_task = cpu->current_task = task_ref(cpu->idle_task);
        idle_task->state = TASK_RUNNING;
    } else {
        UNREACHABLE();
    }
    idle_task->cpu = cpu;
    pagemap_switch(idle_task->vm->pagemap);

    arch_enable_interrupts();
    sched_yield();
    do_idle();
}

void sched_yield(void) {
    SCOPED_DISABLE_INTERRUPTS();

    struct cpu* cpu = cpu_get_current();
    struct task* prev_task = cpu->current_task;
    ASSERT_PTR(prev_task);

    if (prev_task->state == TASK_WAKING) {
        // The task was woken up after preparing to sleep but before actually
        // sleeping. Continue running the current task.
        prev_task->state = TASK_RUNNING;
        return;
    }

    if (!ready_queue.head && prev_task->state == TASK_RUNNING) {
        // No other task is ready to run. Continue running the current task.
        return;
    }

    struct task* next_task = dequeue_ready();
    if (!next_task) {
        if (prev_task->state == TASK_RUNNING) {
            // No other task is ready to run. Continue running the current task.
            return;
        }
        // No ready tasks. Run the idle task.
        next_task = task_ref(cpu->idle_task);
        next_task->state = TASK_RUNNING;
    }
    ASSERT(!next_task->cpu);
    ASSERT(next_task != prev_task);

    next_task->cpu = cpu;
    cpu->current_task = next_task;
    pagemap_switch(next_task->vm->pagemap);
    arch_switch_context(prev_task, next_task);
}

void sched_reschedule(struct task* task) {
    ASSERT(!arch_interrupts_enabled());

    if (!task)
        return;

    ASSERT_PTR(task->cpu);
    bool was_running = task->state == TASK_RUNNING;
    task->cpu = NULL;

    bool is_ready = false;
    if (was_running) {
        // The task continues to be runnable.
        is_ready = true;
    } else {
        unsigned state = TASK_WAKING;
        if (atomic_compare_exchange_strong(&task->state, &state,
                                           TASK_RUNNING)) {
            // The task was woken up after preparing to sleep but before
            // actually sleeping. Make it runnable again.
            is_ready = true;
        }
    }

    if (is_ready && task != cpu_get_current()->idle_task)
        enqueue_ready(task);

    task_unref(task);
}

bool sched_wake(struct task* task) {
    unsigned state = task->state;
    for (;;) {
        switch (state) {
        case TASK_INTERRUPTIBLE:
        case TASK_UNINTERRUPTIBLE:
        case TASK_IDLE:
        case TASK_STOPPED:
            // Sleeping
            break;
        case TASK_RUNNING:
        case TASK_DEAD:
        case TASK_WAKING:
            // Not sleeping
            return false;
        default:
            UNREACHABLE();
        }

        if (task->cpu) {
            // The task changed its state to the sleeping state, but it is still
            // running on a CPU. Let the task itself wake up when it yields.
            if (!atomic_compare_exchange_weak(&task->state, &state,
                                              TASK_WAKING))
                continue;
            state = TASK_WAKING;
            if (task->cpu) {
                // The task is still running on a CPU, so it will handle
                // the wakeup itself.
                return true;
            }
            // The task finished running on the CPU in the meantime, so we need
            // to wake it up ourselves.
        }
        if (atomic_compare_exchange_strong(&task->state, &state,
                                           TASK_RUNNING)) {
            // The task is not running on any CPU, and we are the first one to
            // wake it up, so we can put it in the ready queue.
            enqueue_ready(task);
            return true;
        }
    }
}

#define FIXED_SHIFT 11
#define FIXED_1 (1 << FIXED_SHIFT)
#define FIXED_INT(x) ((x) >> FIXED_SHIFT)
#define FIXED_FRAC(x) FIXED_INT(((x) & (FIXED_1 - 1)) * 100)

#define LOAD_FREQ (5 * CLK_TCK + 1)
#define EXP_1 1884
#define EXP_5 2014
#define EXP_15 2037

static unsigned long fold_load(unsigned long load, unsigned long exp,
                               unsigned long active) {
    unsigned long x = load * exp + active * (FIXED_1 - exp);
    if (active >= load)
        x += FIXED_1 - 1;
    return x / FIXED_1;
}

static _Atomic(unsigned long) loads[3];

static void update_loads(void) {
    static unsigned long next_update_time;
    if (!next_update_time)
        next_update_time = uptime + LOAD_FREQ;
    if ((long)(uptime - next_update_time) < 0)
        return;

    size_t num_active = 0;
    {
        SCOPED_LOCK(spinlock, &tasks_lock);
        for (struct tree_node* node = tree_first(&tasks); node;
             node = tree_next(node)) {
            struct task* task = CONTAINER_OF(node, struct task, tree_node);
            switch (task->state) {
            case TASK_RUNNING:
            case TASK_UNINTERRUPTIBLE:
                ++num_active;
                break;
            }
        }
    }

    unsigned long active = num_active * FIXED_1;
    loads[0] = fold_load(loads[0], EXP_1, active);
    loads[1] = fold_load(loads[1], EXP_5, active);
    loads[2] = fold_load(loads[2], EXP_15, active);

    next_update_time += LOAD_FREQ;
}

void sched_get_loads(unsigned long out_loads[3]) {
    for (size_t i = 0; i < 3; ++i)
        out_loads[i] = loads[i] << (SI_LOAD_SHIFT - FIXED_SHIFT);
}

int proc_print_loadavg(struct file* file, struct vec* vec) {
    (void)file;

    unsigned long v[3];
    for (size_t i = 0; i < 3; ++i)
        v[i] = loads[i] + FIXED_1 / 200;

    size_t num_tasks = 0;
    size_t num_running = 0;
    {
        SCOPED_LOCK(spinlock, &tasks_lock);
        for (struct tree_node* node = tree_first(&tasks); node;
             node = tree_next(node)) {
            struct task* task = CONTAINER_OF(node, struct task, tree_node);
            ++num_tasks;
            if (task->state == TASK_RUNNING)
                ++num_running;
        }
    }

    return vec_printf(vec, "%lu.%02lu %lu.%02lu %lu.%02lu %zu/%zu %d\n",
                      FIXED_INT(v[0]), FIXED_FRAC(v[0]), FIXED_INT(v[1]),
                      FIXED_FRAC(v[1]), FIXED_INT(v[2]), FIXED_FRAC(v[2]),
                      num_running, num_tasks, task_alloc_tid(0));
}

void sched_tick(struct registers* regs) {
    ASSERT(!arch_interrupts_enabled());

    bool preempted_in_user_mode = arch_is_user_mode(regs);
    if (preempted_in_user_mode)
        ++current->user_ticks;
    else
        ++current->kernel_ticks;

    if (cpu_get_current() == cpu_get_bsp())
        update_loads();

    sched_yield();

    if (!preempted_in_user_mode)
        return;

    struct sigaction act;
    int signum = ASSERT_OK(signal_pop(&act));
    if (signum > 0)
        signal_handle(regs, signum, &act);
}

DEFINE_LOCKED(waitqueue, struct waitqueue, spinlock, lock)

size_t waitqueue_wake_n(struct waitqueue* wq, size_t n) {
    SCOPED_LOCK(waitqueue, wq);
    size_t count = 0;
    for (struct waiter* waiter = wq->head; waiter && count < n;
         waiter = waiter->next) {
        if (waiter_wake(waiter))
            ++count;
    }
    return count;
}

size_t waitqueue_wake_all(struct waitqueue* wq) {
    SCOPED_LOCK(waitqueue, wq);
    size_t count = 0;
    for (struct waiter* waiter = wq->head; waiter; waiter = waiter->next) {
        if (waiter_wake(waiter))
            ++count;
    }
    return count;
}

static void waiter_cancel(struct waiter* waiter) {
    if (!waiter->task)
        return;
    struct waitqueue* wq = ASSERT_PTR(waiter->wq);
    SCOPED_LOCK(waitqueue, wq);
    if (waiter->prev)
        waiter->prev->next = waiter->next;
    else
        wq->head = waiter->next;
    if (waiter->next)
        waiter->next->prev = waiter->prev;
    else
        wq->tail = waiter->prev;
    waiter->task = NULL;
    waiter->prev = waiter->next = NULL;
    current->state = TASK_RUNNING;
}

void __waiter_init(struct waiter* waiter, struct waitqueue* wq,
                   unsigned state) {
    ASSERT(arch_interrupts_enabled());
    switch (state) {
    case TASK_INTERRUPTIBLE:
    case TASK_UNINTERRUPTIBLE:
    case TASK_IDLE:
        break;
    default:
        UNREACHABLE();
    }
    *waiter = (struct waiter){
        .wq = wq,
        .state = state,
    };
    SCOPED_DISABLE_INTERRUPTS();
    if (state == TASK_INTERRUPTIBLE && task_has_pending_signals()) {
        waiter->interrupted = true;
        return;
    }
    {
        SCOPED_LOCK(waitqueue, wq);
        // Add the waiter to the end of the queue to ensure FIFO order of
        // wakeups.
        waiter->task = current;
        waiter->prev = wq->tail;
        if (waiter->prev)
            waiter->prev->next = waiter;
        else
            wq->head = waiter;
        wq->tail = waiter;
        current->state = state;
    }
    if (state == TASK_INTERRUPTIBLE && task_has_pending_signals()) {
        waiter_cancel(waiter);
        waiter->interrupted = true;
    }
}

void __waiter_deinit(struct waiter* waiter) {
    waiter_cancel(waiter);
    *waiter = (struct waiter){0};
}

bool waiter_wake(struct waiter* waiter) {
    struct waitqueue* wq = ASSERT_PTR(waiter->wq);
    SCOPED_LOCK(waitqueue, wq);
    struct task* task = waiter->task;
    if (!task)
        return false;
    return sched_wake(task);
}

NODISCARD static int wait(struct waiter* waiter, bool interruptible) {
    ASSERT(arch_interrupts_enabled());
    if (interruptible) {
        ASSERT(waiter->task || waiter->interrupted);
        ASSERT(waiter->state == TASK_INTERRUPTIBLE);
    } else {
        ASSERT_PTR(waiter->task);
        ASSERT(!waiter->interrupted);
    }
    if (waiter->interrupted)
        return -EINTR;
    sched_yield();
    if (interruptible && task_has_pending_signals()) {
        waiter->interrupted = true;
        return -EINTR;
    }
    return 0;
}

void waiter_wait(struct waiter* waiter) { ASSERT_OK(wait(waiter, false)); }

int waiter_wait_interruptible(struct waiter* waiter) {
    return wait(waiter, true);
}
