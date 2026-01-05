#include "private.h"
#include <kernel/api/sys/syscall.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>

long sys_ni_syscall(void) { return -ENOSYS; }

struct syscall {
    const char* name;
    uintptr_t handler;
    unsigned flags;
};

static struct syscall syscalls[] = {
#define F(name, handler, flags)                                                \
    [SYS_##name] = {                                                           \
        #name,                                                                 \
        (uintptr_t)(handler),                                                  \
        (flags),                                                               \
    },
    ENUMERATE_SYSCALLS(F)
#undef F
};

NODISCARD static long do_syscall(struct registers* regs, unsigned* out_flags) {
    if (regs->rax >= ARRAY_SIZE(syscalls))
        return -ENOSYS;

    struct syscall* syscall = syscalls + regs->rax;
    if (!syscall->handler)
        return -ENOSYS;

    if (out_flags)
        *out_flags = syscall->flags;

    if (syscall->handler == (uintptr_t)sys_ni_syscall) {
        if (cmdline_contains("ni_syscall_log"))
            kprintf("syscall: unimplemented syscall %s"
                    "(%#lx, %#lx, %#lx, %#lx, %#lx, %#lx)\n",
                    syscall->name, regs->rbx, regs->rcx, regs->rdx, regs->rsi,
                    regs->rdi, regs->rbp);
    }

    typedef long (*regs_fn)(struct registers*, long, long, long, long, long,
                            long);
    typedef long (*no_regs_fn)(long, long, long, long, long, long);

    if (syscall->flags & SYSCALL_RAW_REGISTERS)
        return ((regs_fn)syscall->handler)(regs, regs->rbx, regs->rcx,
                                           regs->rdx, regs->rsi, regs->rdi,
                                           regs->rbp);

    return ((no_regs_fn)syscall->handler)(regs->rbx, regs->rcx, regs->rdx,
                                          regs->rsi, regs->rdi, regs->rbp);
}

static void syscall_handler(struct registers* regs) {
    ASSERT((regs->cs & 3) == 3);
    ASSERT((regs->ss & 3) == 3);
    ASSERT(interrupts_enabled());

    unsigned flags = 0;
    long ret = do_syscall(regs, &flags);

    struct sigaction act;
    int signum = signal_pop(&act);
    ASSERT_OK(signum);

    if (flags & SYSCALL_NO_ERROR) {
        regs->rax = ret;
    } else {
        switch (ret) {
        case -ERESTARTSYS:
            if (signum && (act.sa_flags & SA_RESTART)) {
                // If the syscall was interrupted by a signal with a sigaction
                // that has SA_RESTART set, re-execute int instruction to
                // restart the syscall.
                regs->rip -= 2;
            } else {
                // Otherwise, tell the userland that the syscall was
                // interrupted.
                regs->rax = -EINTR;
            }
            break;
        default:
            if (IS_ERR(ret)) {
                // Ensure we don't return kernel internal errors to userland
                ASSERT(ret >= -EMAXERRNO);
            }
            regs->rax = ret;
            break;
        }
    }

    if (signum)
        signal_handle(regs, signum, &act);
}

void syscall_init(void) {
    idt_set_interrupt_handler(SYSCALL_VECTOR, syscall_handler);
    idt_set_gate_user_callable(SYSCALL_VECTOR);
    idt_flush();
}
