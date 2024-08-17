#include "scheduler.h"
#include "api/errno.h"
#include "cpu.h"
#include "interrupts/interrupts.h"
#include "memory/memory.h"
#include "panic.h"
#include "process.h"
#include "system.h"
#include <common/stdio.h>

static struct process* ready_queue;
static struct spinlock ready_queue_lock;
atomic_uint idle_ticks;

static noreturn void do_idle(void) {
    for (;;) {
        ASSERT(interrupts_enabled());
        hlt();
    }
}

void scheduler_init(void) {
    for (size_t i = 0; i < num_cpus; ++i) {
        struct cpu* cpu = cpus[i];
        char comm[SIZEOF_MEMBER(struct process, comm)];
        (void)snprintf(comm, sizeof(comm), "idle/%u", i);
        struct process* idle = process_create(comm, do_idle);
        ASSERT_OK(idle);
        cpu->idle_process = idle;
    }
}

void enqueue_ready(struct process* process) {
    ASSERT(process);
    ASSERT(process->state != PROCESS_STATE_DEAD &&
           process->state != PROCESS_STATE_BLOCKED);

    process->ready_queue_next = NULL;

    spinlock_lock(&ready_queue_lock);
    if (ready_queue) {
        struct process* it = ready_queue;
        for (;;) {
            ASSERT(it != process);
            if (!it->ready_queue_next)
                break;
            it = it->ready_queue_next;
        }
        it->ready_queue_next = process;
    } else {
        ready_queue = process;
    }
    spinlock_unlock(&ready_queue_lock);
}

static struct process* dequeue_ready(void) {
    spinlock_lock(&ready_queue_lock);
    if (!ready_queue) {
        spinlock_unlock(&ready_queue_lock);
        return cpu_get_current()->idle_process;
    }
    struct process* process = ready_queue;
    ASSERT(process->state != PROCESS_STATE_DEAD);
    ready_queue = process->ready_queue_next;
    process->ready_queue_next = NULL;
    spinlock_unlock(&ready_queue_lock);
    return process;
}

void scheduler_register(struct process* process) {
    ASSERT(process);
    ASSERT(process->state == PROCESS_STATE_RUNNING);
    process_ref(process);

    spinlock_lock(&all_processes_lock);
    struct process* prev = NULL;
    struct process* it = all_processes;
    while (it && it->pid < process->pid) {
        prev = it;
        it = it->all_processes_next;
    }
    if (prev) {
        process->all_processes_next = it;
        prev->all_processes_next = process;
    } else {
        process->all_processes_next = all_processes;
        all_processes = process;
    }
    spinlock_unlock(&all_processes_lock);

    enqueue_ready(process);
}

static void unblock_processes(void) {
    spinlock_lock(&all_processes_lock);

    if (!all_processes) {
        spinlock_unlock(&all_processes_lock);
        return;
    }

    for (struct process* it = all_processes; it; it = it->all_processes_next) {
        if (it->state != PROCESS_STATE_BLOCKED)
            continue;

        ASSERT(it->unblock);
        bool interrupted =
            it->pending_signals && !(it->block_flags & BLOCK_UNINTERRUPTIBLE);
        if (interrupted || it->unblock(it->block_data)) {
            it->unblock = NULL;
            it->block_data = NULL;
            it->block_flags = 0;
            it->block_was_interrupted = interrupted;
            it->state = PROCESS_STATE_RUNNING;
            process_ref(it);
            enqueue_ready(it);
        }
    }

    spinlock_unlock(&all_processes_lock);
}

noreturn void switch_context(void) {
    cli();

    struct cpu* cpu = cpu_get_current();
    struct process* prev_process = cpu->current_process;
    if (prev_process == cpu->idle_process)
        prev_process = NULL;

    unblock_processes();

    struct process* process = dequeue_ready();
    ASSERT(process);
    ASSERT(process->state != PROCESS_STATE_DEAD);
    cpu->current_process = process;

    vm_enter(process->vm);
    gdt_set_cpu_kernel_stack(process->kernel_stack_top);

    process_handle_pending_signals();

    if (cpu_has_feature(cpu, X86_FEATURE_FXSR))
        __asm__ volatile("fxrstor %0" ::"m"(process->fpu_state));
    else
        __asm__ volatile("frstor %0" ::"m"(process->fpu_state));

    // Call enqueue_ready(prev_process) after switching to the stack of the next
    // process to prevent other CPUs from using the stack of prev_process while
    // we are still using it.
    __asm__ volatile("movl 0x04(%%ebx), %%esp\n" // esp = process->esp
                     "movl 0x08(%%ebx), %%ebp\n" // ebp = process->ebp
                     "test %%eax, %%eax\n"
                     "jz 1f\n"
                     "pushl %%eax\n"
                     "call enqueue_ready\n"
                     "add $4, %%esp\n"
                     "1:\n"
                     "movl %%ebx, %%eax\n"
                     "movl 0x0c(%%eax), %%ebx\n" // ebx = process->ebx
                     "movl 0x10(%%eax), %%esi\n" // esi = process->esi
                     "movl 0x14(%%eax), %%edi\n" // edi = process->edi
                     "movl (%%eax), %%eax\n"     // eax = process->eip
                     "jmp *%%eax"
                     :
                     : "b"(process), "a"(prev_process));
    UNREACHABLE();
}

void scheduler_start(void) { switch_context(); }

void scheduler_yield(bool requeue_current) {
    bool int_flag = push_cli();
    struct cpu* cpu = cpu_get_current();
    struct process* process = cpu->current_process;
    ASSERT(process);

    if (cpu_has_feature(cpu, X86_FEATURE_FXSR))
        __asm__ volatile("fxsave %0" : "=m"(process->fpu_state));
    else
        __asm__ volatile("fnsave %0" : "=m"(process->fpu_state));

    if (process != cpu->idle_process && !requeue_current) {
        process_unref(process);
        cpu->current_process = NULL;
    }

    __asm__ volatile("movl $1f, (%%eax)\n"       // process->eip
                     "movl %%esp, 0x04(%%eax)\n" // process->esp
                     "movl %%ebp, 0x08(%%eax)\n" // process->ebp
                     "movl %%ebx, 0x0c(%%eax)\n" // process->ebx
                     "movl %%esi, 0x10(%%eax)\n" // process->esi
                     "movl %%edi, 0x14(%%eax)\n" // process->edi
                     "jmp switch_context\n"
                     "1:" // switch_context() will jump back here
                     :
                     : "a"(process)
                     : "edx", "ecx", "memory");

    pop_cli(int_flag);
}

void scheduler_tick(struct registers* regs) {
    ASSERT(!interrupts_enabled());
    if (!current)
        return;
    if (current == cpu_get_current()->idle_process)
        ++idle_ticks;
    bool in_kernel = (regs->cs & 3) == 0;
    if (!in_kernel)
        process_die_if_needed();
    process_tick(in_kernel);
    scheduler_yield(true);
}

int scheduler_block(unblock_fn unblock, void* data, int flags) {
    ASSERT(!current->unblock);
    ASSERT(!current->block_data);
    current->block_flags = 0;
    current->block_was_interrupted = false;

    if (unblock(data))
        return 0;

    bool int_flag = push_cli();

    current->unblock = unblock;
    current->block_data = data;
    current->block_flags = flags;
    current->state = PROCESS_STATE_BLOCKED;

    scheduler_yield(false);

    pop_cli(int_flag);

    return current->block_was_interrupted ? -EINTR : 0;
}
