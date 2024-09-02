#include "scheduler.h"
#include "cpu.h"
#include "interrupts/interrupts.h"
#include "memory/memory.h"
#include "panic.h"
#include "system.h"
#include "task.h"
#include <common/stdio.h>

static struct task* ready_queue;
static struct spinlock ready_queue_lock;

static noreturn void do_idle(void) {
    for (;;) {
        ASSERT(interrupts_enabled());
        hlt();
    }
}

void scheduler_init(void) {
    for (size_t i = 0; i < num_cpus; ++i) {
        struct cpu* cpu = cpus[i];
        char comm[SIZEOF_FIELD(struct task, comm)];
        (void)snprintf(comm, sizeof(comm), "idle/%u", i);
        struct task* idle = task_create(comm, do_idle);
        ASSERT_OK(idle);
        cpu->idle_task = idle;
    }
}

void enqueue_ready(struct task* task) {
    ASSERT(task);
    ASSERT(task->state == TASK_RUNNING);

    task->ready_queue_next = NULL;

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
        return cpu_get_current()->idle_task;
    }
    struct task* task = ready_queue;
    ASSERT(task->state != TASK_DEAD);
    ready_queue = task->ready_queue_next;
    task->ready_queue_next = NULL;
    spinlock_unlock(&ready_queue_lock);
    return task;
}

void scheduler_register(struct task* task) {
    ASSERT(task);
    ASSERT(task->state == TASK_RUNNING);
    task_ref(task);

    spinlock_lock(&all_tasks_lock);
    struct task* prev = NULL;
    struct task* it = all_tasks;
    while (it && it->tid < task->tid) {
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

static void unblock_tasks(void) {
    spinlock_lock(&all_tasks_lock);

    if (!all_tasks) {
        spinlock_unlock(&all_tasks_lock);
        return;
    }

    for (struct task* it = all_tasks; it; it = it->all_tasks_next) {
        if (it->state != TASK_UNINTERRUPTIBLE &&
            it->state != TASK_INTERRUPTIBLE)
            continue;

        ASSERT(it->unblock);
        bool interrupted = it->state == TASK_INTERRUPTIBLE &&
                           (it->pending_signals & ~it->blocked_signals);
        if (interrupted || it->unblock(it->block_data)) {
            it->unblock = NULL;
            it->block_data = NULL;
            it->interrupted = interrupted;
            it->state = TASK_RUNNING;
            task_ref(it);
            enqueue_ready(it);
        }
    }

    spinlock_unlock(&all_tasks_lock);
}

noreturn void switch_context(void) {
    cli();

    struct cpu* cpu = cpu_get_current();
    struct task* prev_task = cpu->current_task;
    if (prev_task == cpu->idle_task)
        prev_task = NULL;

    unblock_tasks();

    struct task* task = dequeue_ready();
    ASSERT(task);
    ASSERT(task->state == TASK_RUNNING);
    cpu->current_task = task;

    vm_enter(task->vm);
    gdt_set_cpu_kernel_stack(task->kernel_stack_top);

    if (cpu_has_feature(cpu, X86_FEATURE_FXSR))
        __asm__ volatile("fxrstor %0" ::"m"(task->fpu_state));
    else
        __asm__ volatile("frstor %0" ::"m"(task->fpu_state));

    // Call enqueue_ready(prev_task) after switching to the stack of the next
    // task to prevent other CPUs from using the stack of prev_task while
    // we are still using it.
    __asm__ volatile("movl 0x04(%%ebx), %%esp\n" // esp = task->esp
                     "movl 0x08(%%ebx), %%ebp\n" // ebp = task->ebp
                     "test %%eax, %%eax\n"
                     "jz 1f\n"
                     "pushl %%eax\n"
                     "call enqueue_ready\n"
                     "add $4, %%esp\n"
                     "1:\n"
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

void scheduler_start(void) { switch_context(); }

void scheduler_yield(bool requeue_current) {
    bool int_flag = push_cli();
    struct cpu* cpu = cpu_get_current();
    struct task* task = cpu->current_task;
    ASSERT(task);

    if (cpu_has_feature(cpu, X86_FEATURE_FXSR))
        __asm__ volatile("fxsave %0" : "=m"(task->fpu_state));
    else
        __asm__ volatile("fnsave %0" : "=m"(task->fpu_state));

    if (task != cpu->idle_task && !requeue_current) {
        task_unref(task);
        cpu->current_task = NULL;
    }

    __asm__ volatile("movl $1f, (%%eax)\n"       // task->eip
                     "movl %%esp, 0x04(%%eax)\n" // task->esp
                     "movl %%ebp, 0x08(%%eax)\n" // task->ebp
                     "movl %%ebx, 0x0c(%%eax)\n" // task->ebx
                     "movl %%esi, 0x10(%%eax)\n" // task->esi
                     "movl %%edi, 0x14(%%eax)\n" // task->edi
                     "jmp switch_context\n"
                     "1:" // switch_context() will jump back here
                     :
                     : "a"(task)
                     : "edx", "ecx", "memory");

    pop_cli(int_flag);
}

void scheduler_tick(struct registers* regs) {
    ASSERT(!interrupts_enabled());
    if (!current)
        return;

    bool in_kernel = (regs->cs & 3) == 0;
    task_tick(in_kernel);
    scheduler_yield(true);
    if (in_kernel)
        return;

    struct sigaction act;
    int signum = task_pop_signal(&act);
    ASSERT_OK(signum);
    if (signum > 0)
        task_handle_signal(regs, signum, &act);
}

int scheduler_block(unblock_fn unblock, void* data, int flags) {
    ASSERT(!current->unblock);
    ASSERT(!current->block_data);
    current->interrupted = false;

    if (unblock(data))
        return 0;

    bool int_flag = push_cli();

    current->unblock = unblock;
    current->block_data = data;
    current->state = (flags & BLOCK_UNINTERRUPTIBLE) ? TASK_UNINTERRUPTIBLE
                                                     : TASK_INTERRUPTIBLE;

    scheduler_yield(false);

    pop_cli(int_flag);

    return current->interrupted ? -EINTR : 0;
}
