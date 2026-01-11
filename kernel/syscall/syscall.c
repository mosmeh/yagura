#include <kernel/api/errno.h>
#include <kernel/api/sys/syscall.h>
#include <kernel/arch/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/syscall/syscall.h>
#include <kernel/system.h>
#include <kernel/task/task.h>

long sys_ni_syscall(void) { return -ENOSYS; }

NODISCARD static long dispatch(const struct syscall_abi* abi,
                               struct registers* regs, unsigned* out_flags) {
    if (out_flags)
        *out_flags = 0;

    unsigned long number;
    unsigned long args[6];
    abi->decode(regs, &number, args);

    if (number >= abi->table_len)
        return -ENOSYS;

    const struct syscall* syscall = abi->table + number;
    if (!syscall->handler)
        return -ENOSYS;

    if (out_flags)
        *out_flags = syscall->flags;

    if (syscall->handler == (uintptr_t)sys_ni_syscall) {
        if (cmdline_contains("ni_syscall_log"))
            kprintf("syscall: unimplemented syscall %s"
                    "(%#lx, %#lx, %#lx, %#lx, %#lx, %#lx)\n",
                    syscall->name, args[0], args[1], args[2], args[3], args[4],
                    args[5]);
    }

    typedef long (*regs_fn)(struct registers*, unsigned long, unsigned long,
                            unsigned long, unsigned long, unsigned long,
                            unsigned long);
    typedef long (*no_regs_fn)(unsigned long, unsigned long, unsigned long,
                               unsigned long, unsigned long, unsigned long);

    if (syscall->flags & SYSCALL_RAW_REGISTERS)
        return ((regs_fn)syscall->handler)(regs, args[0], args[1], args[2],
                                           args[3], args[4], args[5]);

    return ((no_regs_fn)syscall->handler)(args[0], args[1], args[2], args[3],
                                          args[4], args[5]);
}

void syscall_handle(const struct syscall_abi* abi, struct registers* regs) {
    ASSERT(arch_interrupts_enabled());

    unsigned flags = 0;
    long ret = dispatch(abi, regs, &flags);

    struct sigaction act;
    int signum = signal_pop(&act);
    ASSERT_OK(signum);

    if (flags & SYSCALL_NO_ERROR) {
        abi->set_return_value(regs, ret);
    } else {
        switch (ret) {
        case -ERESTARTSYS:
            if (signum && (act.sa_flags & SA_RESTART)) {
                // If the syscall was interrupted by a signal with a sigaction
                // that has SA_RESTART set, restart the syscall.
                abi->restart(regs);
            } else {
                // Otherwise, tell the userland that the syscall was
                // interrupted.
                abi->set_return_value(regs, -EINTR);
            }
            break;
        default:
            if (IS_ERR(ret)) {
                // Ensure we don't return kernel internal errors to userland
                ASSERT(ret >= -EMAXERRNO);
            }
            abi->set_return_value(regs, ret);
            break;
        }
    }

    if (signum)
        signal_handle(regs, signum, &act);
}
