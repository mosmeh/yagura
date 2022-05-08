#include "scheduler.h"
#include "api/errno.h"
#include "interrupts.h"
#include "memory.h"
#include "memory/memory.h"
#include "panic.h"
#include "process.h"
#include "system.h"

struct process* all_processes;
static struct process* ready_queue;
static struct process* idle;

void scheduler_register(struct process* process) {
    ASSERT(process->state == PROCESS_STATE_RUNNING);

    bool int_flag = push_cli();
    process->next_in_all_processes = all_processes;
    all_processes = process;
    pop_cli(int_flag);

    scheduler_enqueue(process);
}

void scheduler_unregister(struct process* process) {
    bool int_flag = push_cli();

    struct process* prev = NULL;
    for (struct process* it = all_processes; it;) {
        if (it != process) {
            prev = it;
            it = it->next_in_all_processes;
            continue;
        }
        if (prev)
            prev->next_in_all_processes = it->next_in_all_processes;
        else
            all_processes = it->next_in_all_processes;
    }

    pop_cli(int_flag);
}

void scheduler_enqueue(struct process* process) {
    ASSERT(process->state != PROCESS_STATE_DEAD);

    bool int_flag = push_cli();

    process->next_in_ready_queue = NULL;
    if (ready_queue) {
        struct process* it = ready_queue;
        while (it->next_in_ready_queue)
            it = it->next_in_ready_queue;
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

        ASSERT(it->should_unblock);
        if (it->pending_signals || it->should_unblock(it->blocker_data)) {
            it->should_unblock = NULL;
            it->blocker_data = NULL;
            it->blocker_was_interrupted = it->pending_signals != 0;
            it->state = PROCESS_STATE_RUNNING;
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
    idle = process_create_kernel_process(do_idle);
    ASSERT_OK(idle);
}

static noreturn void switch_to_next_process(void) {
    unblock_processes();

    current = scheduler_deque();
    ASSERT(current);
    ASSERT(current->state != PROCESS_STATE_DEAD);

    paging_switch_page_directory(current->pd);
    gdt_set_kernel_stack(current->stack_top);

    process_handle_pending_signals();

    __asm__ volatile("fxrstor %0" ::"m"(current->fpu_state));

    __asm__ volatile("mov %%eax, %%ebp\n"
                     "mov %%ecx, %%esp\n"
                     "mov $1, %%eax;\n"
                     "sti\n"
                     "jmp *%%edx"
                     :
                     : "d"(current->eip), "a"(current->ebp), "c"(current->esp),
                       "b"(current->ebx), "S"(current->esi), "D"(current->edi));
    UNREACHABLE();
}

void scheduler_yield(bool requeue_current) {
    cli();
    ASSERT(current);

    if (current == idle)
        switch_to_next_process();

    uint32_t eip = read_eip();
    if (eip == 1)
        return;

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

    __asm__ volatile("fxsave %0" : "=m"(current->fpu_state));

    if (requeue_current)
        scheduler_enqueue(current);

    switch_to_next_process();
}

void scheduler_tick(bool in_kernel) {
    if (!in_kernel)
        process_die_if_needed();
    process_tick(in_kernel);
    scheduler_yield(true);
}

int scheduler_block(bool (*should_unblock)(void*), void* data) {
    ASSERT(!current->should_unblock);
    ASSERT(!current->blocker_data);

    if (should_unblock(data))
        return 0;

    current->state = PROCESS_STATE_BLOCKED;
    current->should_unblock = should_unblock;
    current->blocker_data = data;
    current->blocker_was_interrupted = false;

    scheduler_yield(false);

    return current->blocker_was_interrupted ? -EINTR : 0;
}
