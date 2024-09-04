#include "syscall.h"
#include "unimplemented.h"
#include <kernel/api/sys/reboot.h>
#include <kernel/api/sys/syscall.h>
#include <kernel/api/unistd.h>
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

int sys_newuname(struct utsname* user_buf) {
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

#define F(name)                                                                \
    static int sys_ni_##name(struct registers* regs) {                         \
        if (cmdline_contains("ni_syscall_log"))                                \
            kprintf("syscall: unimplemented syscall " #name                    \
                    "(%#x, %#x, %#x, %#x, %#x, %#x)\n",                        \
                    regs->ebx, regs->ecx, regs->edx, regs->esi, regs->edi,     \
                    regs->ebp);                                                \
        return -ENOSYS;                                                        \
    }
ENUMERATE_UNIMPLEMENTED_SYSCALLS(F)
#undef F

struct syscall {
    uintptr_t handler;
    unsigned flags;
};

static struct syscall syscalls[] = {
#define F(name)                                                                \
    [SYS_##name] = {                                                           \
        (uintptr_t)sys_ni_##name,                                              \
        SYSCALL_RAW_REGISTERS,                                                 \
    },
    ENUMERATE_UNIMPLEMENTED_SYSCALLS(F)
#undef F

#define F(name, handler, flags)                                                \
    [SYS_##name] = {                                                           \
        (uintptr_t)(handler),                                                  \
        (flags),                                                               \
    },
        ENUMERATE_SYSCALLS(F)
#undef F
};

static int do_syscall(struct registers* regs, unsigned* out_flags) {
    if (regs->eax >= ARRAY_SIZE(syscalls))
        return -ENOSYS;

    struct syscall* syscall = syscalls + regs->eax;
    if (!syscall->handler)
        return -ENOSYS;

    if (out_flags)
        *out_flags = syscall->flags;

    typedef int (*regs_fn)(struct registers*, int, int, int, int, int, int);
    typedef int (*no_regs_fn)(int, int, int, int, int, int);

    if (syscall->flags & SYSCALL_RAW_REGISTERS)
        return ((regs_fn)syscall->handler)(regs, regs->ebx, regs->ecx,
                                           regs->edx, regs->esi, regs->edi,
                                           regs->ebp);

    return ((no_regs_fn)syscall->handler)(regs->ebx, regs->ecx, regs->edx,
                                          regs->esi, regs->edi, regs->ebp);
}

static void syscall_handler(struct registers* regs) {
    ASSERT((regs->cs & 3) == 3);
    ASSERT((regs->ds & 3) == 3);
    ASSERT((regs->es & 3) == 3);
    ASSERT((regs->fs & 3) == 3);
    ASSERT((regs->gs & 3) == 3);
    ASSERT((regs->user_ss & 3) == 3);
    ASSERT(interrupts_enabled());

    unsigned flags = 0;
    int ret = do_syscall(regs, &flags);

    struct sigaction act;
    int signum = task_pop_signal(&act);
    ASSERT_OK(signum);

    if (flags & SYSCALL_NO_ERROR) {
        regs->eax = ret;
    } else {
        switch (ret) {
        case -ERESTARTSYS:
            if (signum && (act.sa_flags & SA_RESTART)) {
                // If the syscall was interrupted by a signal with a sigaction
                // that has SA_RESTART set, re-execute int instruction to
                // restart the syscall.
                regs->eip -= 2;
            } else {
                // Otherwise, tell the userland that the syscall was
                // interrupted.
                regs->eax = -EINTR;
            }
            break;
        default:
            if (IS_ERR(ret)) {
                // Ensure we don't return kernel internal errors to userland
                ASSERT(ret > -EMAXERRNO);
            }
            regs->eax = ret;
            break;
        }
    }

    if (signum)
        task_handle_signal(regs, signum, &act);
}

void syscall_init(void) {
    idt_set_interrupt_handler(SYSCALL_VECTOR, syscall_handler);
    idt_set_gate_user_callable(SYSCALL_VECTOR);
    idt_flush();
}
