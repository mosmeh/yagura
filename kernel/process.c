#include "process.h"
#include "api/err.h"
#include "asm_wrapper.h"
#include "boot_defs.h"
#include "kernel/fs/fs.h"
#include "kernel/interrupts.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "mem.h"
#include "panic.h"
#include "system.h"
#include <common/extra.h>
#include <common/string.h>
#include <stdatomic.h>

#define USER_HEAP_START 0x100000

process* current;
static process* queue;
static process* idle;
static atomic_int next_pid;

static process* process_deque(void) {
    bool int_flag = push_cli();

    process* p = queue;
    if (p) {
        queue = p->next;
        p->next = NULL;
    } else {
        p = idle;
    }

    pop_cli(int_flag);
    return p;
}

void process_enqueue(process* p) {
    bool int_flag = push_cli();

    p->next = NULL;
    if (queue) {
        process* it = queue;
        while (it->next)
            it = it->next;
        it->next = p;
    } else {
        queue = p;
    }

    pop_cli(int_flag);
}

pid_t process_generate_next_pid(void) {
    return atomic_fetch_add_explicit(&next_pid, 1, memory_order_acq_rel);
}

static process* create_kernel_process(void (*entry_point)(void)) {
    process* p = kmalloc(sizeof(process));
    if (!p)
        return ERR_PTR(-ENOMEM);
    memset(p, 0, sizeof(process));

    p->id = process_generate_next_pid();
    p->heap_next_vaddr = USER_HEAP_START;
    p->eip = (uintptr_t)entry_point;
    p->next = NULL;

    p->pd = mem_create_page_directory();
    if (IS_ERR(p->pd))
        return ERR_CAST(p->pd);

    int rc = file_descriptor_table_init(&p->fd_table);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    void* stack = kmalloc(STACK_SIZE);
    if (!stack)
        return ERR_PTR(-ENOMEM);
    p->stack_top = (uintptr_t)stack + STACK_SIZE;
    p->esp = p->ebp = p->stack_top;

    return p;
}

static noreturn void do_idle(void) {
    for (;;) {
        KASSERT(interrupts_enabled());
        hlt();
    }
}

extern unsigned char kernel_page_directory[];
extern unsigned char stack_top[];

void process_init(void) {
    atomic_init(&next_pid, 0);

    current = kmalloc(sizeof(process));
    KASSERT(current);
    memset(current, 0, sizeof(process));
    current->id = process_generate_next_pid();
    current->pd =
        (page_directory*)((uintptr_t)kernel_page_directory + KERNEL_VADDR);
    current->stack_top = (uintptr_t)stack_top;
    current->heap_next_vaddr = USER_HEAP_START;
    KASSERT(IS_OK(file_descriptor_table_init(&current->fd_table)));
    current->next = NULL;

    gdt_set_kernel_stack(current->stack_top);

    idle = create_kernel_process(do_idle);
    KASSERT(IS_OK(idle));
}

static noreturn void switch_to_next_process(void) {
    cli();

    current = process_deque();
    KASSERT(current);

    mem_switch_page_directory(current->pd);
    gdt_set_kernel_stack(current->stack_top);

    __asm__ volatile("mov %0, %%edx\n"
                     "mov %1, %%ebp\n"
                     "mov %2, %%esp\n"
                     "mov $1, %%eax;\n"
                     "sti\n"
                     "jmp *%%edx"
                     :
                     : "g"(current->eip), "g"(current->ebp), "g"(current->esp),
                       "b"(current->ebx), "S"(current->esi), "D"(current->edi)
                     : "eax", "edx");
    KUNREACHABLE();
}

void process_switch(void) {
    cli();
    KASSERT(current);

    if (current != idle) {
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

        process_enqueue(current);
    }

    switch_to_next_process();
}

pid_t process_spawn_kernel_process(void (*entry_point)(void)) {
    process* p = create_kernel_process(entry_point);
    if (IS_ERR(p))
        return PTR_ERR(p);
    process_enqueue(p);
    return p->id;
}

noreturn void process_exit(int status) {
    kprintf("\x1b[34mProcess #%d exited with status %d\x1b[m\n", current->id,
            status);
    switch_to_next_process();
}

pid_t process_get_pid(void) { return current->id; }

uintptr_t process_alloc_virtual_address_range(uintptr_t size) {
    uintptr_t current_ptr = current->heap_next_vaddr;
    uintptr_t aligned_ptr = round_up(current_ptr, PAGE_SIZE);
    uintptr_t next_ptr = aligned_ptr + size;
    if (next_ptr > USER_STACK_BASE - PAGE_SIZE)
        return -ENOMEM;

    current->heap_next_vaddr = next_ptr;
    return aligned_ptr;
}

int process_alloc_file_descriptor(struct file* file) {
    file_description* desc = current->fd_table.entries;
    for (int i = 0; i < FD_TABLE_CAPACITY; ++i, ++desc) {
        if (desc->file)
            continue;

        desc->file = file;
        desc->offset = 0;
        return i;
    }
    return -EMFILE;
}

int process_free_file_descriptor(int fd) {
    if (fd >= FD_TABLE_CAPACITY)
        return -EBADF;

    file_description* desc = current->fd_table.entries + fd;
    if (!desc->file)
        return -EBADF;

    desc->file = NULL;
    desc->offset = 0;
    return 0;
}

file_description* process_get_file_description(int fd) {
    if (fd >= FD_TABLE_CAPACITY)
        return ERR_PTR(-EBADF);

    file_description* desc = current->fd_table.entries + fd;
    if (!desc->file)
        return ERR_PTR(-EBADF);

    return desc;
}
