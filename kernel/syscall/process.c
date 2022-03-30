#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/boot_defs.h>
#include <kernel/kmalloc.h>
#include <kernel/mem.h>
#include <kernel/process.h>
#include <kernel/system.h>

noreturn uintptr_t sys_exit(int status) { process_exit(status); }

uintptr_t sys_getpid(void) { return process_get_pid(); }

uintptr_t sys_yield(void) {
    process_switch();
    return 0;
}

void return_to_userland(registers);

uintptr_t sys_fork(registers* regs) {
    process* p = kmalloc(sizeof(process));
    if (!p)
        return -ENOMEM;
    memset(p, 0, sizeof(process));

    p->pd = mem_clone_current_page_directory();
    if (IS_ERR(p->pd))
        return PTR_ERR(p->pd);

    p->id = process_generate_next_pid();
    p->eip = (uintptr_t)return_to_userland;
    p->heap_next_vaddr = current->heap_next_vaddr;
    p->ebx = current->ebx;
    p->esi = current->esi;
    p->edi = current->edi;
    p->next = NULL;

    int rc = file_descriptor_table_clone_from(&p->fd_table, &current->fd_table);
    if (IS_ERR(rc))
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

    process_enqueue(p);

    return p->id;
}
