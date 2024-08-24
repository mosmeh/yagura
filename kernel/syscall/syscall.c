#include "syscall.h"
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/reboot.h>
#include <kernel/api/unistd.h>
#include <kernel/boot_defs.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/task.h>
#include <kernel/time.h>

int sys_reboot(int howto) {
    switch (howto) {
    case RB_AUTOBOOT:
        kprint("Restarting system.\n");
        reboot();
    case RB_HALT:
        kprint("System halted.\n");
        halt();
    case RB_POWEROFF:
        kprint("Power down.\n");
        poweroff();
    default:
        return -1;
    }
}

long sys_sysconf(int name) {
    switch (name) {
    case _SC_ARG_MAX:
        return ARG_MAX;
    case _SC_CLK_TCK:
        return CLK_TCK;
    case _SC_MONOTONIC_CLOCK:
        return 1;
    case _SC_OPEN_MAX:
        return OPEN_MAX;
    case _SC_PAGESIZE:
        return PAGE_SIZE;
    case _SC_SYMLOOP_MAX:
        return SYMLOOP_MAX;
    default:
        return -EINVAL;
    }
}

int sys_uname(struct utsname* user_buf) {
    if (copy_to_user(user_buf, utsname(), sizeof(struct utsname)))
        return -EFAULT;
    return 0;
}

int sys_dbgprint(const char* user_str) {
    char str[1024];
    ssize_t str_len = strncpy_from_user(str, user_str, sizeof(str));
    if (IS_ERR(str_len))
        return str_len;
    if ((size_t)str_len >= sizeof(str))
        return -E2BIG;
    return kprint(user_str);
}

typedef uintptr_t (*syscall_handler_fn)(uintptr_t arg1, uintptr_t arg2,
                                        uintptr_t arg3, uintptr_t arg4);

static syscall_handler_fn syscall_handlers[NUM_SYSCALLS] = {
#define ENUM_ITEM(name) (syscall_handler_fn)(uintptr_t) sys_##name,
    ENUMERATE_SYSCALLS(ENUM_ITEM)
#undef ENUM_ITEM
};

static int do_syscall(struct registers* regs) {
    if (regs->eax >= NUM_SYSCALLS)
        return -ENOSYS;

    syscall_handler_fn handler = syscall_handlers[regs->eax];
    ASSERT(handler);

    switch (regs->eax) {
    case SYS_fork:
        return sys_fork(regs);
    case SYS_clone:
        return sys_clone(regs, regs->ebx, (void*)regs->ecx);
    }
    return handler(regs->edx, regs->ecx, regs->ebx, regs->esi);
}

static void syscall_handler(struct registers* regs) {
    ASSERT((regs->cs & 3) == 3);
    ASSERT((regs->ds & 3) == 3);
    ASSERT((regs->es & 3) == 3);
    ASSERT((regs->fs & 3) == 3);
    ASSERT((regs->gs & 3) == 3);
    ASSERT((regs->user_ss & 3) == 3);
    ASSERT(interrupts_enabled());

    task_die_if_needed();
    regs->eax = do_syscall(regs);
    task_die_if_needed();
}

void syscall_init(void) {
    idt_set_interrupt_handler(SYSCALL_VECTOR, syscall_handler);
    idt_set_gate_user_callable(SYSCALL_VECTOR);
    idt_flush();
}
