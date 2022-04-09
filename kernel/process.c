#include "process.h"
#include "boot_defs.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "mem.h"
#include "panic.h"
#include "scheduler.h"
#include "system.h"
#include <common/extra.h>
#include <stdatomic.h>
#include <string.h>

#define USER_HEAP_START 0x100000

process* current;
static atomic_int next_pid;

extern unsigned char kernel_page_directory[];
extern unsigned char stack_top[];

void process_init(void) {
    atomic_init(&next_pid, 0);

    current = kmalloc(sizeof(process));
    ASSERT(current);
    memset(current, 0, sizeof(process));
    current->id = process_generate_next_pid();
    current->pd =
        (page_directory*)((uintptr_t)kernel_page_directory + KERNEL_VADDR);
    current->stack_top = (uintptr_t)stack_top;
    current->heap_next_vaddr = USER_HEAP_START;
    ASSERT_OK(file_descriptor_table_init(&current->fd_table));
    current->next = NULL;

    gdt_set_kernel_stack(current->stack_top);
}

process* process_create_kernel_process(void (*entry_point)(void)) {
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

pid_t process_spawn_kernel_process(void (*entry_point)(void)) {
    process* p = process_create_kernel_process(entry_point);
    if (IS_ERR(p))
        return PTR_ERR(p);
    scheduler_enqueue(p);
    return p->id;
}

pid_t process_generate_next_pid(void) {
    return atomic_fetch_add_explicit(&next_pid, 1, memory_order_acq_rel);
}

noreturn void process_exit(int status) {
    if (status != 0)
        kprintf("\x1b[31mProcess %d exited with status %d\x1b[m\n", current->id,
                status);
    scheduler_yield(false);
    UNREACHABLE();
}

uintptr_t process_alloc_virtual_addr_range(uintptr_t size) {
    uintptr_t current_ptr = current->heap_next_vaddr;
    uintptr_t aligned_ptr = round_up(current_ptr, PAGE_SIZE);
    uintptr_t next_ptr = aligned_ptr + size;
    if (next_ptr > KERNEL_VADDR)
        return -ENOMEM;

    current->heap_next_vaddr = next_ptr;
    return aligned_ptr;
}

int process_alloc_file_descriptor(file_description* desc) {
    file_description** it = current->fd_table.entries;
    for (int i = 0; i < FD_TABLE_CAPACITY; ++i, ++it) {
        if (*it)
            continue;
        *it = desc;
        return i;
    }
    return -EMFILE;
}

int process_free_file_descriptor(int fd) {
    if (fd >= FD_TABLE_CAPACITY)
        return -EBADF;

    file_description** desc = current->fd_table.entries + fd;
    if (!*desc)
        return -EBADF;
    *desc = NULL;
    return 0;
}

file_description* process_get_file_description(int fd) {
    if (fd >= FD_TABLE_CAPACITY)
        return ERR_PTR(-EBADF);

    file_description** desc = current->fd_table.entries + fd;
    if (!*desc)
        return ERR_PTR(-EBADF);

    return *desc;
}
