#include "interrupts.h"
#include "mem.h"
#include "panic.h"
#include "process.h"
#include "system.h"

static process* ready_queue;
static process* blocked_processes;
static process* idle;

static process* scheduler_deque(void) {
    bool int_flag = push_cli();

    process* p = ready_queue;
    if (p) {
        ready_queue = p->next;
        p->next = NULL;
    } else {
        p = idle;
    }

    pop_cli(int_flag);
    return p;
}

void scheduler_enqueue(process* p) {
    bool int_flag = push_cli();

    p->next = NULL;
    if (ready_queue) {
        process* it = ready_queue;
        while (it->next)
            it = it->next;
        it->next = p;
    } else {
        ready_queue = p;
    }

    pop_cli(int_flag);
}

static void unblock_processes(void) {
    if (!blocked_processes)
        return;

    process* prev = NULL;
    process* it = blocked_processes;
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
    }
}

extern unsigned char kernel_page_directory[];
extern unsigned char stack_top[];

void scheduler_init(void) {
    idle = process_create_kernel_process(do_idle);
    ASSERT_OK(idle);
}

static noreturn void switch_to_next_process(void) {
    cli();

    unblock_processes();

    current = scheduler_deque();
    ASSERT(current);

    mem_switch_page_directory(current->pd);
    gdt_set_kernel_stack(current->stack_top);

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

    uint32_t esp, ebp, ebx, esi, edi;
    __asm__ volatile("mov %%esp, %0" : "=m"(esp));
    __asm__ volatile("mov %%ebp, %0" : "=m"(ebp));
    __asm__ volatile("mov %%ebx, %0" : "=m"(ebx));
    __asm__ volatile("mov %%esi, %0" : "=m"(esi));
    __asm__ volatile("mov %%edi, %0" : "=m"(edi));

    current->eip = eip;
    current->esp = esp;
    current->ebp = ebp;
    current->ebx = ebx;
    current->esi = esi;
    current->edi = edi;

    if (requeue_current)
        scheduler_enqueue(current);

    switch_to_next_process();
}

void scheduler_block(bool (*should_unblock)(void*), void* data) {
    ASSERT(!current->should_unblock);
    ASSERT(!current->blocker_data);
    current->should_unblock = should_unblock;
    current->blocker_data = data;

    cli();

    current->next = NULL;
    if (blocked_processes) {
        process* it = blocked_processes;
        while (it->next)
            it = it->next;
        it->next = current;
    } else {
        blocked_processes = current;
    }

    scheduler_yield(false);
}
