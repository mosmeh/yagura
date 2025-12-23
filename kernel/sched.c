#include <common/stdio.h>
#include <common/string.h>
#include <kernel/cpu.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/sched.h>
#include <kernel/system.h>
#include <kernel/task.h>
#include <kernel/time.h>

static noreturn void do_idle(void) {
    for (;;) {
        ASSERT(interrupts_enabled());
        hlt();
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
        (void)snprintf(comm, sizeof(comm), "idle/%u", i);
        struct task* idle = task_create(comm, do_idle);
        ASSERT_PTR(idle);
        cpu->idle_task = idle;
    }
}

static struct task* ready_queue;
static struct spinlock ready_queue_lock;

static void enqueue_ready(struct task* task) {
    ASSERT(task);
    ASSERT(task->state == TASK_RUNNING);
    ASSERT(!task->ready_queue_next);
    ASSERT(!task->blocked_next);
    task_ref(task);

    spinlock_lock(&ready_queue_lock);
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
    spinlock_unlock(&ready_queue_lock);
}

static struct task* dequeue_ready(void) {
    spinlock_lock(&ready_queue_lock);
    if (!ready_queue) {
        spinlock_unlock(&ready_queue_lock);
        struct task* task = task_ref(cpu_get_current()->idle_task);
        task->state = TASK_RUNNING;
        return task;
    }
    struct task* task = ready_queue;
    ASSERT(task->state == TASK_RUNNING);
    ready_queue = task->ready_queue_next;
    task->ready_queue_next = NULL;
    spinlock_unlock(&ready_queue_lock);
    return task;
}

void sched_register(struct task* task) {
    ASSERT(task);
    ASSERT(task->state == TASK_RUNNING);
    task_ref(task);

    spinlock_lock(&all_tasks_lock);
    struct task* prev = NULL;
    struct task* it = all_tasks;
    while (it && it->tid < task->tid) {
        ASSERT(it != task);
        prev = it;
        it = it->all_tasks_next;
    }
    if (prev) {
        task->all_tasks_next = it;
        prev->all_tasks_next = task;
    } else {
        task->all_tasks_next = all_tasks;
        all_tasks = task;
    }
    spinlock_unlock(&all_tasks_lock);

    enqueue_ready(task);
}

static struct task* blocked_tasks;
static struct spinlock blocked_tasks_lock;

static void add_blocked(struct task* task) {
    ASSERT(task);
    ASSERT(!task->blocked_next);
    spinlock_lock(&blocked_tasks_lock);
    task->blocked_next = blocked_tasks;
    blocked_tasks = task_ref(task);
    spinlock_unlock(&blocked_tasks_lock);
}

static void unblock_tasks(void) {
    spinlock_lock(&blocked_tasks_lock);

    struct task* prev = NULL;
    for (struct task* it = blocked_tasks; it;) {
        sigset_t signals = it->pending_signals & ~it->blocked_signals;

        bool ready = false;
        switch (it->state) {
        case TASK_UNINTERRUPTIBLE:
        case TASK_INTERRUPTIBLE: {
            ASSERT(it->unblock);
            bool interrupted = it->state == TASK_INTERRUPTIBLE && signals;
            if (interrupted || it->unblock(it->block_data)) {
                it->unblock = NULL;
                it->block_data = NULL;
                it->interrupted = interrupted;
                ready = true;
            }
            break;
        }
        case TASK_STOPPED:
            if (signals & sigmask(SIGCONT))
                ready = true;
            break;
        default:
            UNREACHABLE();
        }

        if (!ready) {
            prev = it;
            it = it->blocked_next;
            continue;
        }

        if (prev)
            prev->blocked_next = it->blocked_next;
        else
            blocked_tasks = it->blocked_next;

        struct task* next = it->blocked_next;
        it->blocked_next = NULL;
        it->state = TASK_RUNNING;
        enqueue_ready(it);
        task_unref(it);
        it = next;
    }

    spinlock_unlock(&blocked_tasks_lock);
}

void __reschedule(struct task* task) {
    if (!task)
        return;
    switch (task->state) {
    case TASK_RUNNING:
        if (task != cpu_get_current()->idle_task)
            enqueue_ready(task);
        break;
    case TASK_UNINTERRUPTIBLE:
    case TASK_INTERRUPTIBLE:
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

noreturn static void switch_context(void) {
    cli();

    struct cpu* cpu = cpu_get_current();
    struct task* prev_task = cpu->current_task;
    cpu->current_task = NULL;

    unblock_tasks();

    struct task* task = dequeue_ready();
    ASSERT(task);
    ASSERT(task->state == TASK_RUNNING);
    cpu->current_task = task;

    page_directory_switch(task->vm->page_directory);

    gdt_set_cpu_kernel_stack(task->kernel_stack_top);
    memcpy(cpu->gdt + GDT_ENTRY_TLS_MIN, task->tls, sizeof(task->tls));

    if (cpu_has_feature(cpu, X86_FEATURE_FXSR))
        __asm__ volatile("fxrstor %0" ::"m"(task->fpu_state));
    else
        __asm__ volatile("frstor %0" ::"m"(task->fpu_state));

    // Call __reschedule(prev_task) after switching to the stack of the next
    // task to prevent other CPUs from using the stack of prev_task while
    // we are still using it.
    __asm__ volatile("movl 0x04(%%ebx), %%esp\n" // esp = task->esp
                     "movl 0x08(%%ebx), %%ebp\n" // ebp = task->ebp
                     "pushl %%eax\n"
                     "call __reschedule\n"
                     "add $4, %%esp\n"
                     "movl %%ebx, %%eax\n"
                     "movl 0x0c(%%eax), %%ebx\n" // ebx = task->ebx
                     "movl 0x10(%%eax), %%esi\n" // esi = task->esi
                     "movl 0x14(%%eax), %%edi\n" // edi = task->edi
                     "movl (%%eax), %%eax\n"     // eax = task->eip
                     "jmp *%%eax"
                     :
                     : "b"(task), "a"(prev_task));
    UNREACHABLE();
}

noreturn void __switch_context(void) { switch_context(); }

void sched_start(void) {
    cli();
    struct cpu* cpu = cpu_get_current();
    struct task* task = cpu->current_task;
    if (task) {
        // Turn this task into the idle task for this CPU.
        cpu->idle_task = task;
        sti();
        sched_yield();
        do_idle();
    }
    switch_context();
}

void sched_yield(void) {
    bool int_flag = push_cli();
    struct cpu* cpu = cpu_get_current();
    struct task* task = cpu->current_task;
    ASSERT(task);

    if (cpu_has_feature(cpu, X86_FEATURE_FXSR))
        __asm__ volatile("fxsave %0" : "=m"(task->fpu_state));
    else
        __asm__ volatile("fnsave %0" : "=m"(task->fpu_state));

    __asm__ volatile("movl $1f, (%%eax)\n"       // task->eip
                     "movl %%esp, 0x04(%%eax)\n" // task->esp
                     "movl %%ebp, 0x08(%%eax)\n" // task->ebp
                     "movl %%ebx, 0x0c(%%eax)\n" // task->ebx
                     "movl %%esi, 0x10(%%eax)\n" // task->esi
                     "movl %%edi, 0x14(%%eax)\n" // task->edi
                     "jmp __switch_context\n"
                     "1:" // switch_context() will jump back here
                     :
                     : "a"(task)
                     : "edx", "ecx", "memory");

    pop_cli(int_flag);
}

void sched_tick(struct registers* regs) {
    ASSERT(!interrupts_enabled());
    ASSERT(current);

    bool preempted_in_kernel = (regs->cs & 3) == 0;
    if (preempted_in_kernel)
        ++current->kernel_ticks;
    else
        ++current->user_ticks;

    sched_yield();

    if (preempted_in_kernel)
        return;

    struct sigaction act;
    int signum = task_pop_signal(&act);
    ASSERT_OK(signum);
    if (signum > 0)
        task_handle_signal(regs, signum, &act);
}

static bool never_unblock(void* data) {
    (void)data;
    return false;
}

int sched_block(unblock_fn unblock, void* data, int flags) {
    ASSERT(!current->unblock);
    ASSERT(!current->block_data);
    current->interrupted = false;

    if (unblock && unblock(data))
        return 0;

    bool int_flag = push_cli();

    current->unblock = unblock ? unblock : never_unblock;
    current->block_data = data;
    current->state = (flags & BLOCK_UNINTERRUPTIBLE) ? TASK_UNINTERRUPTIBLE
                                                     : TASK_INTERRUPTIBLE;

    sched_yield();

    pop_cli(int_flag);

    return current->interrupted ? -EINTR : 0;
}

static bool unblock_sleep(void* data) {
    const struct timespec* deadline = data;
    struct timespec now;
    ASSERT_OK(time_now(CLOCK_MONOTONIC, &now));
    return timespec_compare(&now, deadline) >= 0;
}

void sched_sleep(const struct timespec* duration) {
    struct timespec deadline;
    ASSERT_OK(time_now(CLOCK_MONOTONIC, &deadline));
    timespec_add(&deadline, duration);
    ASSERT_OK(sched_block(unblock_sleep, &deadline, BLOCK_UNINTERRUPTIBLE));
}
