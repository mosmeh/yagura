#include "scheduler.h"
#include "api/errno.h"
#include "cpu.h"
#include "interrupts.h"
#include "memory/memory.h"
#include "panic.h"
#include "process.h"
#include "system.h"

static struct process* ready_queue;
static struct process* idle;
atomic_uint idle_ticks;

void scheduler_register(struct process* process) {
    ASSERT(process->state == PROCESS_STATE_RUNNABLE);
    process_ref(process);

    bool int_flag = push_cli();
    struct process* prev = NULL;
    struct process* it = all_processes;
    while (it && it->pid < process->pid) {
        prev = it;
        it = it->next_in_all_processes;
    }
    if (prev) {
        process->next_in_all_processes = it;
        prev->next_in_all_processes = process;
    } else {
        process->next_in_all_processes = all_processes;
        all_processes = process;
    }
    pop_cli(int_flag);

    scheduler_enqueue(process);
}

void scheduler_enqueue(struct process* process) {
    ASSERT(process->state != PROCESS_STATE_DEAD &&
           process->state != PROCESS_STATE_BLOCKED);

    bool int_flag = push_cli();

    process->next_in_ready_queue = NULL;
    if (ready_queue) {
        struct process* it = ready_queue;
        ASSERT(it != process);
        while (it->next_in_ready_queue) {
            it = it->next_in_ready_queue;
            ASSERT(it != process);
        }
        it->next_in_ready_queue = process;
    } else {
        ready_queue = process;
    }

    pop_cli(int_flag);
}

static struct process* scheduler_deque(void) {
    ASSERT(!interrupts_enabled());
    if (!ready_queue)
        return idle;
    struct process* process = ready_queue;
    ready_queue = process->next_in_ready_queue;
    process->next_in_ready_queue = NULL;
    ASSERT(process->state != PROCESS_STATE_DEAD);
    return process;
}

static void unblock_processes(void) {
    ASSERT(!interrupts_enabled());
    if (!all_processes)
        return;

    for (struct process* it = all_processes; it;
         it = it->next_in_all_processes) {
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
            scheduler_enqueue(it);
        }
    }
}

static noreturn void do_idle(void) {
    for (;;) {
        ASSERT(interrupts_enabled());
        hlt();
        ASSERT(interrupts_enabled());
        scheduler_yield(false);
    }
}

void scheduler_init(void) {
    idle = process_create("idle", do_idle);
    ASSERT_OK(idle);
}

static noreturn void switch_to_next_process(void) {
    ASSERT(!interrupts_enabled());
    unblock_processes();

    current = scheduler_deque();
    ASSERT(current);
    ASSERT(current->state != PROCESS_STATE_DEAD);

    vm_enter(current->vm);
    gdt_set_kernel_stack(current->kernel_stack_top);

    process_handle_pending_signals();

    if (cpu_has_feature(X86_FEATURE_FXSR))
        __asm__ volatile("fxrstor %0" ::"m"(current->fpu_state));
    else
        __asm__ volatile("frstor %0" ::"m"(current->fpu_state));

    if (current->state == PROCESS_STATE_RUNNABLE) {
        current->state = PROCESS_STATE_RUNNING;

        // current->eip points to an entry point, so we have to enable
        // interrupts here
        __asm__ volatile("mov %%eax, %%ebp\n"
                         "mov %%ecx, %%esp\n"
                         "mov $0, %%eax;\n"
                         "sti\n"
                         "jmp *%%edx"
                         :
                         : "d"(current->eip), "a"(current->ebp),
                           "c"(current->esp), "b"(current->ebx),
                           "S"(current->esi), "D"(current->edi));
    } else {
        // current->eip points to the read_eip() line in scheduler_yield(),
        // and pop_cli handles enabling interrupts, so we don't enable
        // interrupts here
        __asm__ volatile("mov %%eax, %%ebp\n"
                         "mov %%ecx, %%esp\n"
                         "mov $1, %%eax;\n" // read_eip() returns 1
                         "jmp *%%edx"
                         :
                         : "d"(current->eip), "a"(current->ebp),
                           "c"(current->esp), "b"(current->ebx),
                           "S"(current->esi), "D"(current->edi));
    }
    UNREACHABLE();
}

void scheduler_yield(bool requeue_current) {
    bool int_flag = push_cli();
    ASSERT(current);

    if (current == idle) {
        // because we don't save the context for the idle task, it has to be
        // launched as a brand new task every time.
        idle->state = PROCESS_STATE_RUNNABLE;

        // skip saving the context
        switch_to_next_process();
        UNREACHABLE();
    }

    uint32_t eip = read_eip();
    if (eip == 1) {
        // we came back from switch_to_next_process()
        pop_cli(int_flag);
        return;
    }

    uint32_t esp;
    __asm__ volatile("mov %%esp, %0" : "=m"(esp));
    uint32_t ebp;
    __asm__ volatile("mov %%ebp, %0" : "=m"(ebp));
    uint32_t ebx;
    __asm__ volatile("mov %%ebx, %0" : "=m"(ebx));
    uint32_t esi;
    __asm__ volatile("mov %%esi, %0" : "=m"(esi));
    uint32_t edi;
    __asm__ volatile("mov %%edi, %0" : "=m"(edi));

    current->eip = eip;
    current->esp = esp;
    current->ebp = ebp;
    current->ebx = ebx;
    current->esi = esi;
    current->edi = edi;

    if (cpu_has_feature(X86_FEATURE_FXSR))
        __asm__ volatile("fxsave %0" : "=m"(current->fpu_state));
    else
        __asm__ volatile("fnsave %0" : "=m"(current->fpu_state));

    if (requeue_current)
        scheduler_enqueue(current);
    else
        process_unref(current);

    switch_to_next_process();
    UNREACHABLE();
}

void scheduler_tick(bool in_kernel) {
    if (current == idle)
        ++idle_ticks;
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

    current->state = PROCESS_STATE_BLOCKED;
    current->unblock = unblock;
    current->block_data = data;
    current->block_flags = flags;

    scheduler_yield(false);

    pop_cli(int_flag);

    return current->block_was_interrupted ? -EINTR : 0;
}
