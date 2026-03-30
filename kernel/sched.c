#include <common/stdio.h>
#include <common/string.h>
#include <kernel/api/sys/sysinfo.h>
#include <kernel/containers/vec.h>
#include <kernel/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>
#include <kernel/sched.h>
#include <kernel/system.h>
#include <kernel/task/signal.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

static _Noreturn void do_idle(void) {
    for (;;) {
        ASSERT(arch_interrupts_enabled());
        arch_wait_for_interrupt();
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

static _Atomic(struct task*) ready_queue;
static struct spinlock ready_queue_lock;

static void enqueue_ready(struct task* task) {
    ASSERT_PTR(task);
    ASSERT(task->state == TASK_RUNNING);
    ASSERT(!task->ready_queue_next);
    ASSERT(!task->blocked_next);
    task_ref(task);

    SCOPED_LOCK(spinlock, &ready_queue_lock);
    if (ready_queue) {
        struct task* it = ready_queue;
        for (;;) {
            ASSERT(it != task);
            if (!it->ready_queue_next)
                break;
            it = it->ready_queue_next;
        }
        it->ready_queue_next = task;
    } else {
        ready_queue = task;
    }
}

static struct task* dequeue_ready(void) {
    SCOPED_LOCK(spinlock, &ready_queue_lock);
    struct task* task = ready_queue;
    if (task) {
        ASSERT(task->state == TASK_RUNNING);
        ready_queue = task->ready_queue_next;
        task->ready_queue_next = NULL;
    }
    return task;
}

void sched_register(struct task* task) {
    ASSERT_PTR(task);
    ASSERT(task->state == TASK_RUNNING);
    task_ref(task);
    ++task->thread_group->num_running_tasks;

    {
        SCOPED_LOCK(spinlock, &tasks_lock);
        struct task* prev = NULL;
        struct task* it = tasks;
        while (it && it->tid < task->tid) {
            ASSERT(it != task);
            prev = it;
            it = it->tasks_next;
        }
        if (prev) {
            task->tasks_next = it;
            prev->tasks_next = task;
        } else {
            task->tasks_next = tasks;
            tasks = task;
        }
    }

    enqueue_ready(task);
}

static struct task* blocked_tasks;
static struct spinlock blocked_tasks_lock;

static void add_blocked(struct task* task) {
    ASSERT_PTR(task);
    ASSERT(!task->blocked_next);
    SCOPED_LOCK(spinlock, &blocked_tasks_lock);
    task->blocked_next = blocked_tasks;
    blocked_tasks = task_ref(task);
}

static void get_pending_signals(struct task* task, sigset_t* out_set) {
    SCOPED_LOCK(spinlock, &tasks_lock);
    task_get_pending_signals(task, out_set);
}

static void wake_tasks(void) {
    SCOPED_LOCK(spinlock, &blocked_tasks_lock);

    struct task* prev = NULL;
    for (struct task* task = blocked_tasks; task;) {
        bool ready = false;
        switch (task->state) {
        case TASK_INTERRUPTIBLE:
        case TASK_UNINTERRUPTIBLE:
        case TASK_IDLE: {
            struct wait_state* wait = &task->wait_state;
            ASSERT_PTR(wait->wake);

            bool interrupted = false;
            if (task->state == TASK_INTERRUPTIBLE) {
                sigset_t signals;
                get_pending_signals(task, &signals);
                interrupted = !sigisemptyset(&signals);
            }

            if (interrupted || wait->wake(wait->ctx)) {
                *wait = (struct wait_state){.interrupted = interrupted};
                ready = true;
            }
            break;
        }
        case TASK_STOPPED: {
            sigset_t signals;
            get_pending_signals(task, &signals);
            if (sigismember(&signals, SIGCONT))
                ready = true;
            break;
        }
        default:
            UNREACHABLE();
        }

        if (!ready) {
            prev = task;
            task = task->blocked_next;
            continue;
        }

        if (prev)
            prev->blocked_next = task->blocked_next;
        else
            blocked_tasks = task->blocked_next;

        struct task* next = task->blocked_next;
        task->blocked_next = NULL;
        task->state = TASK_RUNNING;
        task->exit_status = 0;
        enqueue_ready(task);
        task_unref(task);
        task = next;
    }
}

void sched_start(void) {
    arch_disable_interrupts();
    struct cpu* cpu = cpu_get_current();
    if (cpu->current_task) {
        // Turn this task into the idle task for this CPU.
        cpu->idle_task = cpu->current_task;
    } else if (cpu->idle_task) {
        // No current task. Run the idle task.
        cpu->current_task = task_ref(cpu->idle_task);
        cpu->current_task->state = TASK_RUNNING;
    } else {
        UNREACHABLE();
    }
    pagemap_switch(cpu->current_task->vm->pagemap);
    arch_enable_interrupts();
    sched_yield();
    do_idle();
}

void sched_yield(void) {
    SCOPED_DISABLE_INTERRUPTS();

    struct cpu* cpu = cpu_get_current();
    struct task* prev_task = cpu->current_task;
    ASSERT_PTR(prev_task);

    wake_tasks();

    if (!ready_queue && prev_task->state == TASK_RUNNING) {
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
    ASSERT(next_task != prev_task);

    cpu->current_task = next_task;
    pagemap_switch(next_task->vm->pagemap);
    arch_switch_context(prev_task, next_task);
}

void sched_reschedule(struct task* task) {
    if (!task)
        return;
    switch (task->state) {
    case TASK_RUNNING:
        if (task != cpu_get_current()->idle_task)
            enqueue_ready(task);
        break;
    case TASK_INTERRUPTIBLE:
    case TASK_UNINTERRUPTIBLE:
    case TASK_IDLE:
    case TASK_STOPPED:
        add_blocked(task);
        break;
    case TASK_DEAD:
        break;
    default:
        UNREACHABLE();
    }
    task_unref(task);
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
        for (struct task* task = tasks; task; task = task->tasks_next) {
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
        for (struct task* task = tasks; task; task = task->tasks_next) {
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

static bool never_wake(void* ctx) {
    (void)ctx;
    return false;
}

NODISCARD static int wait(wake_fn wake, void* ctx, unsigned state) {
    ASSERT(current->state == TASK_RUNNING);

    struct wait_state* wait = &current->wait_state;
    ASSERT(!wait->wake);
    ASSERT(!wait->ctx);
    *wait = (struct wait_state){0};

    if (wake && wake(ctx))
        return 0;

    SCOPED_DISABLE_INTERRUPTS();

    *wait = (struct wait_state){
        .wake = wake ? wake : never_wake,
        .ctx = ctx,
    };
    current->state = state;

    sched_yield();

    ASSERT(current->state == TASK_RUNNING);

    int rc = wait->interrupted ? -EINTR : 0;
    *wait = (struct wait_state){0};
    return rc;
}

void sched_wait(wake_fn wake, void* ctx) {
    ASSERT_OK(wait(wake, ctx, TASK_UNINTERRUPTIBLE));
}

void sched_wait_as_idle(wake_fn wake, void* ctx) {
    ASSERT_OK(wait(wake, ctx, TASK_IDLE));
}

int sched_wait_interruptible(wake_fn wake, void* ctx) {
    return wait(wake, ctx, TASK_INTERRUPTIBLE);
}
