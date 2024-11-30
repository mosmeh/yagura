#include "syscall.h"
#include "unimplemented.h"
#include <kernel/api/sys/syscall.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/task.h>

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
    const char* name;
    uintptr_t handler;
    unsigned flags;
};

static struct syscall syscalls[] = {
#define F(name)                                                                \
    [SYS_##name] = {                                                           \
        #name,                                                                 \
        (uintptr_t)sys_ni_##name,                                              \
        SYSCALL_RAW_REGISTERS,                                                 \
    },
    ENUMERATE_UNIMPLEMENTED_SYSCALLS(F)
#undef F

#define F(name, handler, flags)                                                \
    [SYS_##name] = {                                                           \
        #name,                                                                 \
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

    if (cmdline_contains("syscall_log"))
        kprintf("syscall: %s(%#x, %#x, %#x, %#x, %#x, %#x) = ", syscall->name,
                regs->ebx, regs->ecx, regs->edx, regs->esi, regs->edi,
                regs->ebp);

    int ret;
    if (syscall->flags & SYSCALL_RAW_REGISTERS)
        ret = ((regs_fn)syscall->handler)(regs, regs->ebx, regs->ecx, regs->edx,
                                          regs->esi, regs->edi, regs->ebp);
    else
        ret = ((no_regs_fn)syscall->handler)(regs->ebx, regs->ecx, regs->edx,
                                             regs->esi, regs->edi, regs->ebp);

    if (cmdline_contains("syscall_log"))
        kprintf("%#x\n", ret);
    return ret;
}

static void syscall_handler(struct registers* regs) {
    ASSERT((regs->cs & 3) == 3);
    ASSERT((regs->ss & 3) == 3);
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
                ASSERT(ret >= -EMAXERRNO);
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
