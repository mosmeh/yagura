#include "process.h"
#include "asm_wrapper.h"
#include "boot_defs.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "mem.h"
#include "system.h"
#include <common/string.h>
#include <stdbool.h>

#define USERLAND_HEAP_START 0x100000

static process* current;
static process* queue;
static pid_t next_pid = 0;

static process* queue_pop(void) {
    if (!queue)
        return NULL;

    process* p = queue;
    queue = p->next;
    p->next = NULL;
    return p;
}

static void queue_push(process* p) {
    p->next = NULL;

    if (!queue) {
        queue = p;
        return;
    }

    process* it = queue;
    while (it->next)
        it = it->next;
    it->next = p;
}

static void queue_delete(process* p) {
    if (p == queue) {
        queue = p->next;
        return;
    }

    process* prev = NULL;
    process* cur = queue;
    while (cur != p && cur->next) {
        prev = cur;
        cur = cur->next;
    }
    if (cur == p)
        prev->next = p->next;
}

static file_descriptor_table create_fd_table(void) {
    file_descriptor_table table;
    table.entries = kmalloc(FD_TABLE_CAPACITY * sizeof(file_description));
    return table;
}

static file_descriptor_table clone_fd_table(const file_descriptor_table* from) {
    file_descriptor_table table = create_fd_table();
    memcpy(table.entries, from->entries,
           FD_TABLE_CAPACITY * sizeof(file_description));
    return table;
}

extern unsigned char stack_top[];

void process_init(void) {
    cli();

    uintptr_t pd_paddr =
        mem_get_physical_addr((uintptr_t)mem_clone_page_directory());
    mem_switch_page_directory(pd_paddr);

    current = (process*)kmalloc(sizeof(process));
    current->id = next_pid++;
    current->esp = current->ebp = current->eip = 0;
    current->pd_paddr = pd_paddr;
    current->stack_top = (uintptr_t)stack_top;
    current->next_vaddr = USERLAND_HEAP_START;
    current->fd_table = create_fd_table();
    current->next = NULL;

    sti();
}

process* process_current(void) { return (process*)current; }

static void switch_to_next_process(void) {
    current = queue_pop();
    KASSERT(current);

    mem_switch_page_directory(current->pd_paddr);

    gdt_set_kernel_stack(current->stack_top);

    __asm__ volatile("mov %0, %%ebx\n"
                     "mov %1, %%esp\n"
                     "mov %2, %%ebp\n"
                     "mov $1, %%eax;\n"
                     "jmp *%%ebx"
                     :
                     : "r"(current->eip), "r"(current->esp), "r"(current->ebp)
                     : "eax", "ebx");
    KUNREACHABLE();
}

void process_switch(void) {
    if (!current)
        return;

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

    switch_to_next_process();
    KUNREACHABLE();
}

// spawns a process without parent
pid_t process_spawn_kernel_process(void (*entry_point)(void)) {
    cli();

    uintptr_t pd_paddr =
        mem_get_physical_addr((uintptr_t)mem_clone_page_directory());

    process* p = (process*)kmalloc(sizeof(process));
    p->id = next_pid++;
    p->pd_paddr = pd_paddr;
    p->next_vaddr = USERLAND_HEAP_START;
    p->fd_table = create_fd_table();
    p->next = NULL;

    p->eip = (uintptr_t)entry_point;
    p->stack_top = (uintptr_t)kmalloc(STACK_SIZE) + STACK_SIZE;
    p->esp = p->ebp = p->stack_top;

    queue_push(p);

    sti();
    return p->id;
}

noreturn void process_enter_userland(void (*entry_point)(void)) {
    cli();

    gdt_set_kernel_stack(current->stack_top);
    mem_map_virtual_addr_range_to_any_pages(USER_STACK_BASE, USER_STACK_TOP,
                                            MEM_WRITE | MEM_USER);

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
    cli();

    uintptr_t pd_paddr =
        mem_get_physical_addr((uintptr_t)mem_clone_page_directory());

    process* p = (process*)kmalloc(sizeof(process));
    p->id = next_pid++;
    p->pd_paddr = pd_paddr;
    p->stack_top = (uintptr_t)kmalloc(STACK_SIZE) + STACK_SIZE;
    p->next_vaddr = current->next_vaddr;
    p->fd_table = clone_fd_table(&current->fd_table);
    p->next = NULL;

    p->eip = (uintptr_t)return_to_userland;
    p->esp = p->ebp = p->stack_top;

    // push the argument of return_to_userland()
    p->esp -= sizeof(registers);
    registers* new_regs = (registers*)p->esp;
    *new_regs = *regs;
    new_regs->eax = 0; // fork() returns 0 in the child

    queue_push(p);

    sti();
    return p->id;
}

noreturn void process_exit(int status) {
    kprintf("\x1b[34mProcess #%d exited with status %d\x1b[m\n", current->id,
            status);

    queue_delete(current);
    switch_to_next_process();

    while (true)
        pause();
}

pid_t process_get_pid(void) { return current->id; }

int process_alloc_file_descriptor(fs_node* node) {
    file_description* entry = current->fd_table.entries;
    for (int i = 0; i < FD_TABLE_CAPACITY; ++i, ++entry) {
        if (entry->node)
            continue;

        entry->node = node;
        entry->offset = 0;
        return i;
    }
    KPANIC("Too many open files");
}

void process_free_file_descriptor(int fd) {
    file_description* entry = current->fd_table.entries + fd;
    KASSERT(entry->node);
    entry->node = NULL;
    entry->offset = 0;
}
