#include "syscall.h"
#include <kernel/api/errno.h>
#include <kernel/interrupts.h>
#include <kernel/kprintf.h>
#include <kernel/panic.h>
#include <kernel/system.h>

noreturn uintptr_t sys_halt(void) {
    kprintf("System halted\n");
    cli();
    for (;;)
        hlt();
}

uintptr_t sys_dbgputs(const char* str) { return kputs(str); }

typedef uintptr_t (*syscall_handler_fn)();

static syscall_handler_fn syscall_handlers[NUM_SYSCALLS + 1] = {
#define ENUM_ITEM(name) sys_##name,
    ENUMERATE_SYSCALLS(ENUM_ITEM)
#undef ENUM_ITEM
        NULL};

static void syscall_handler(registers* regs) {
    ASSERT((regs->cs & 3) == 3);
    ASSERT((regs->ds & 3) == 3);
    ASSERT((regs->es & 3) == 3);
    ASSERT((regs->fs & 3) == 3);
    ASSERT((regs->gs & 3) == 3);
    ASSERT((regs->user_ss & 3) == 3);
    ASSERT(interrupts_enabled());

    if (regs->eax >= NUM_SYSCALLS) {
        regs->eax = -ENOSYS;
        return;
    }

    syscall_handler_fn handler = syscall_handlers[regs->eax];
    ASSERT(handler);

    if (regs->eax == SYS_fork)
        regs->eax = handler(regs);
    else
        regs->eax = handler(regs->edx, regs->ecx, regs->ebx);
}

void syscall_init(void) {
    idt_register_interrupt_handler(SYSCALL_VECTOR, syscall_handler);
    idt_set_gate_user_callable(SYSCALL_VECTOR);
    idt_flush();
}
