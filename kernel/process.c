#include "process.h"
#include "asm_wrapper.h"
#include "boot_defs.h"
#include "kernel/fs/fs.h"
#include "kernel/interrupts.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "mem.h"
#include "system.h"
#include <common/extra.h>
#include <common/string.h>
#include <stdatomic.h>

#define USERLAND_HEAP_START 0x100000

process* current;
static process* queue;
static process* idle;
static atomic_int next_pid;

static process* queue_pop(void) {
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

static void queue_push(process* p) {
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

static pid_t get_next_pid(void) {
    return atomic_fetch_add_explicit(&next_pid, 1, memory_order_acq_rel);
}

static process* create_kernel_process(void (*entry_point)(void)) {
    process* p = kmalloc(sizeof(process));
    if (!p)
        return NULL;

    p->id = next_pid++;
    p->heap_next_vaddr = USERLAND_HEAP_START;
    p->eip = (uintptr_t)entry_point;
    p->next = NULL;

    p->pd_paddr = mem_clone_current_page_directory_and_get_physical_addr();
    if (addr_is_error(p->pd_paddr))
        return NULL;

    if (file_descriptor_table_init(&p->fd_table) < 0)
        return NULL;

    void* stack = kmalloc(STACK_SIZE);
    if (!stack)
        return NULL;
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

extern unsigned char stack_top[];

void process_init(void) {
    atomic_init(&next_pid, 0);

    uintptr_t pd_paddr =
        mem_clone_current_page_directory_and_get_physical_addr();
    KASSERT(!addr_is_error(pd_paddr));
    mem_switch_page_directory(pd_paddr);

    current = kmalloc(sizeof(process));
    KASSERT(current);
    current->id = get_next_pid();
    current->esp = current->ebp = current->eip = 0;
    current->pd_paddr = pd_paddr;
    current->stack_top = (uintptr_t)stack_top;
    current->heap_next_vaddr = USERLAND_HEAP_START;
    KASSERT(file_descriptor_table_init(&current->fd_table) >= 0);
    current->next = NULL;

    gdt_set_kernel_stack(current->stack_top);

    idle = create_kernel_process(do_idle);
}

static noreturn void switch_to_next_process(void) {
    cli();

    current = queue_pop();
    KASSERT(current);

    mem_switch_page_directory(current->pd_paddr);
    gdt_set_kernel_stack(current->stack_top);

    __asm__ volatile("mov %0, %%ebx\n"
                     "mov %1, %%esp\n"
                     "mov %2, %%ebp\n"
                     "mov $1, %%eax;\n"
                     "sti\n"
                     "jmp *%%ebx"
                     :
                     : "r"(current->eip), "r"(current->esp), "r"(current->ebp)
                     : "eax", "ebx");
    KUNREACHABLE();
}

void process_switch(void) {
    cli();
    KASSERT(current);

    if (current != idle) {
        uint32_t eip = read_eip();
        if (eip == 1)
            return;

        uint32_t esp, ebp;
        __asm__ volatile("mov %%esp, %0" : "=r"(esp));
        __asm__ volatile("mov %%ebp, %0" : "=r"(ebp));

        current->eip = eip;
        current->esp = esp;
        current->ebp = ebp;

        queue_push(current);
    }

    switch_to_next_process();
}

pid_t process_spawn_kernel_process(void (*entry_point)(void)) {
    process* p = kmalloc(sizeof(process));
    if (!p)
        return -ENOMEM;

    uintptr_t pd_paddr =
        mem_clone_current_page_directory_and_get_physical_addr();
    if (addr_is_error(pd_paddr))
        return pd_paddr;

    p->id = next_pid++;
    p->pd_paddr = pd_paddr;
    p->heap_next_vaddr = USERLAND_HEAP_START;
    p->eip = (uintptr_t)entry_point;
    p->next = NULL;

    int rc = file_descriptor_table_init(&p->fd_table);
    if (rc < 0)
        return rc;

    void* stack = kmalloc(STACK_SIZE);
    if (!stack)
        return -ENOMEM;
    p->stack_top = (uintptr_t)stack + STACK_SIZE;
    p->esp = p->ebp = p->stack_top;

    queue_push(p);

    return p->id;
}

int process_enter_userland(void (*entry_point)(void)) {
    int rc = mem_map_to_private_anonymous_region(USER_STACK_BASE, STACK_SIZE,
                                                 MEM_WRITE | MEM_USER);
    if (rc < 0)
        return rc;

    __asm__ volatile("movw $0x23, %%ax\n"
                     "movw %%ax, %%ds\n"
                     "movw %%ax, %%es\n"
                     "movw %%ax, %%fs\n"
                     "movw %%ax, %%gs\n"
                     "movl %0, %%esp\n"
                     "pushl $0x23\n"
                     "pushl %0\n"
                     "pushf\n"
                     "popl %%eax\n"
                     "orl $0x200, %%eax\n" // set IF
                     "pushl %%eax\n"
                     "pushl $0x1b\n"
                     "push %1\n"
                     "iret" ::"i"(USER_STACK_TOP),
                     "r"(entry_point)
                     : "eax");
    KUNREACHABLE();
}

void return_to_userland(registers);

// for syscall
pid_t process_userland_fork(registers* regs) {
    process* p = kmalloc(sizeof(process));
    if (!p)
        return -ENOMEM;

    uintptr_t pd_paddr =
        mem_clone_current_page_directory_and_get_physical_addr();
    if (addr_is_error(pd_paddr))
        return pd_paddr;

    p->id = next_pid++;
    p->pd_paddr = pd_paddr;
    p->eip = (uintptr_t)return_to_userland;
    p->heap_next_vaddr = current->heap_next_vaddr;
    p->next = NULL;

    int rc = file_descriptor_table_clone_from(&p->fd_table, &current->fd_table);
    if (rc < 0)
        return rc;

    void* stack = kmalloc(STACK_SIZE);
    if (!stack)
        return -ENOMEM;
    p->stack_top = (uintptr_t)stack + STACK_SIZE;
    p->esp = p->ebp = p->stack_top;

    // push the argument of return_to_userland()
    p->esp -= sizeof(registers);
    registers* child_regs = (registers*)p->esp;
    *child_regs = *regs;
    child_regs->eax = 0; // fork() returns 0 in the child

    queue_push(p);

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

int process_alloc_file_descriptor(fs_node* node) {
    file_description* desc = current->fd_table.entries;
    for (int i = 0; i < FD_TABLE_CAPACITY; ++i, ++desc) {
        if (desc->node)
            continue;

        desc->node = node;
        desc->offset = 0;
        return i;
    }
    return -EMFILE;
}

int process_free_file_descriptor(int fd) {
    if (fd >= FD_TABLE_CAPACITY)
        return -EBADF;

    file_description* desc = current->fd_table.entries + fd;
    if (!desc->node)
        return -EBADF;

    desc->node = NULL;
    desc->offset = 0;
    return 0;
}

file_description* process_get_file_description(int fd) {
    if (fd >= FD_TABLE_CAPACITY)
        return NULL;

    file_description* desc = current->fd_table.entries + fd;
    if (!desc->node)
        return NULL;

    return desc;
}
