#include "syscall.h"
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/reboot.h>
#include <kernel/api/sys/syscall.h>
#include <kernel/api/unistd.h>
#include <kernel/boot_defs.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/task.h>
#include <kernel/time.h>

int sys_reboot(int magic, int magic2, int op, void* user_arg) {
    if ((unsigned)magic != LINUX_REBOOT_MAGIC1)
        return -EINVAL;
    switch (magic2) {
    case LINUX_REBOOT_MAGIC2:
    case LINUX_REBOOT_MAGIC2A:
    case LINUX_REBOOT_MAGIC2B:
    case LINUX_REBOOT_MAGIC2C:
        break;
    default:
        return -EINVAL;
    }

    switch (op) {
    case LINUX_REBOOT_CMD_RESTART:
        kprint("Restarting system.\n");
        reboot();
    case LINUX_REBOOT_CMD_RESTART2: {
        char arg[1024] = {0};
        int rc = strncpy_from_user(arg, user_arg, sizeof(arg));
        if (IS_ERR(rc))
            return rc;
        arg[sizeof(arg) - 1] = 0;
        kprintf("Restarting system with command '%s'", arg);
        reboot();
    }
    case LINUX_REBOOT_CMD_HALT:
        kprint("System halted.\n");
        halt();
    case LINUX_REBOOT_CMD_POWER_OFF:
        kprint("Power down.\n");
        poweroff();
    default:
        return -EINVAL;
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

static uintptr_t handlers[] = {
#define F(name) [SYS_##name] = (uintptr_t)sys_##name,
    ENUMERATE_SYSCALLS(F)
#undef F
};

static int do_syscall(struct registers* regs) {
    if (regs->eax >= ARRAY_SIZE(handlers))
        return -ENOSYS;

    uintptr_t handler = handlers[regs->eax];
    if (!handler)
        return -ENOSYS;

    typedef int (*regs_fn)(struct registers*, int, int, int, int, int, int);
    typedef int (*no_regs_fn)(int, int, int, int, int, int);

    switch (regs->eax) {
    case SYS_fork:
    case SYS_clone:
        return ((regs_fn)handler)(regs, regs->ebx, regs->ecx, regs->edx,
                                  regs->esi, regs->edi, regs->ebp);
    }
    return ((no_regs_fn)handler)(regs->ebx, regs->ecx, regs->edx, regs->esi,
                                 regs->edi, regs->ebp);
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
