#include "scheduler.h"
#include "interrupts.h"
#include "memory.h"
#include "memory/memory.h"
#include "panic.h"
#include "process.h"
#include "system.h"

struct process* ready_queue;
struct process* blocked_processes;
static struct process* idle;

void scheduler_enqueue(struct process* process) {
    bool int_flag = push_cli();

    process->next = NULL;
    if (ready_queue) {
        struct process* it = ready_queue;
        while (it->next)
            it = it->next;
        it->next = process;
    } else {
        ready_queue = process;
    }

    pop_cli(int_flag);
}

static struct process* scheduler_deque(void) {
    if (!ready_queue)
        return idle;
    struct process* process = ready_queue;
    ready_queue = process->next;
    process->next = NULL;
    return process;
}

static void unblock_processes(void) {
    if (!blocked_processes)
        return;

    struct process* prev = NULL;
    struct process* it = blocked_processes;
    for (;;) {
        ASSERT(it->should_unblock);
        if (it->should_unblock(it->blocker_data)) {
            if (prev)
                prev->next = it->next;
            else
                blocked_processes = it->next;

            it->should_unblock = NULL;
            it->blocker_data = NULL;
            scheduler_enqueue(it);
        }
        if (!it->next)
            return;
        prev = it;
        it = it->next;
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

    paging_switch_page_directory(current->pd);
    gdt_set_kernel_stack(current->stack_top);

    __asm__ volatile("fxrstor %0" ::"m"(current->fpu_state));

    __asm__ volatile("mov %0, %%edx\n"
                     "mov %1, %%eax\n"
                     "mov %2, %%ecx\n"
                     "mov %%eax, %%ebp\n"
                     "mov %%ecx, %%esp\n"
                     "mov $1, %%eax;\n"
                     "sti\n"
                     "jmp *%%edx"
                     :
                     : "g"(current->eip), "g"(current->ebp), "g"(current->esp),
                       "b"(current->ebx), "S"(current->esi), "D"(current->edi)
                     : "eax", "edx", "ecx");
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

void scheduler_block(bool (*should_unblock)(void*), void* data) {
    ASSERT(!current->should_unblock);
    ASSERT(!current->blocker_data);

    if (should_unblock(data))
        return;

    current->should_unblock = should_unblock;
    current->blocker_data = data;

    cli();

    current->next = NULL;
    if (blocked_processes) {
        struct process* it = blocked_processes;
        while (it->next)
            it = it->next;
        it->next = current;
    } else {
        blocked_processes = current;
    }

    scheduler_yield(false);
}
