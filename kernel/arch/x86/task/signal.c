#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/sys/syscall.h>
#include <kernel/arch/x86/task/context.h>
#include <kernel/interrupts.h>
#include <kernel/memory/safe_string.h>
#include <kernel/task/task.h>

extern unsigned char signal_trampoline_start[];
extern unsigned char signal_trampoline_end[];

void signal_trampoline(void) {
    unsigned long dummy;
    __asm__ volatile(
        ".globl signal_trampoline_start, signal_trampoline_end\n"
        "signal_trampoline_start:\n"
        "pop %[num]\n" // pop signum
        "mov %[sigreturn], %[num]\n"
        "int %[syscall_vector]\n"
        "signal_trampoline_end:\n"
        : [num] "=&a"(dummy)
        : [sigreturn] "i"(SYS_sigreturn), [syscall_vector] "i"(SYSCALL_VECTOR));
    __builtin_unreachable();
}

int arch_handle_signal(struct registers* regs, int signum,
                       const struct sigaction* action) {
    struct sigcontext ctx = {
        .regs = *regs,
        .blocked_signals = current->blocked_signals,
    };
    ASSERT((uintptr_t)signal_trampoline_start + sizeof(ctx.trampoline) ==
           (uintptr_t)signal_trampoline_end);
    memcpy(ctx.trampoline, signal_trampoline_start, sizeof(ctx.trampoline));

    uintptr_t sp = regs->sp;

#ifdef ARCH_X86_64
    sp -= 128; // Skip red zone
#endif

    sp = ROUND_DOWN(sp, 16);

    // Push the context of the interrupted task
    sp -= sizeof(struct sigcontext);
    struct sigcontext* user_ctx = (struct sigcontext*)sp;
    if (copy_to_user(user_ctx, &ctx, sizeof(struct sigcontext)))
        return -EFAULT;

    // Push the argument of the signal handler
    sp -= sizeof(long);
    if (copy_to_user((void*)sp, &signum, sizeof(long)))
        return -EFAULT;

    uintptr_t trampoline = (action->sa_flags & SA_RESTORER)
                               ? (uintptr_t)action->sa_restorer
                               : (uintptr_t)user_ctx->trampoline;

    // Push the return address of the signal handler
    sp -= sizeof(uintptr_t);
    if (copy_to_user((void*)sp, &trampoline, sizeof(uintptr_t)))
        return -EFAULT;

    regs->sp = sp;
    regs->ip = (uintptr_t)action->sa_handler;

    return 0;
}

#define FIX_EFLAGS                                                             \
    (X86_EFLAGS_AC | X86_EFLAGS_OF | X86_EFLAGS_DF | X86_EFLAGS_TF |           \
     X86_EFLAGS_SF | X86_EFLAGS_ZF | X86_EFLAGS_AF | X86_EFLAGS_PF |           \
     X86_EFLAGS_CF | X86_EFLAGS_RF)

long sys_sigreturn(struct registers* regs) {
    struct sigcontext ctx;
    if (copy_from_user(&ctx, (void*)regs->sp, sizeof(struct sigcontext)))
        task_crash(SIGSEGV);

    regs->ss = ctx.regs.ss | 3;
    regs->cs = ctx.regs.cs | 3;
    regs->ds = ctx.regs.ds;
    regs->es = ctx.regs.es;
    regs->fs = ctx.regs.fs;
    regs->gs = ctx.regs.gs;

    regs->bx = ctx.regs.bx;
    regs->cx = ctx.regs.cx;
    regs->dx = ctx.regs.dx;
    regs->si = ctx.regs.si;
    regs->di = ctx.regs.di;
    regs->bp = ctx.regs.bp;

#ifdef ARCH_X86_64
    regs->r8 = ctx.regs.r8;
    regs->r9 = ctx.regs.r9;
    regs->r10 = ctx.regs.r10;
    regs->r11 = ctx.regs.r11;
    regs->r12 = ctx.regs.r12;
    regs->r13 = ctx.regs.r13;
    regs->r14 = ctx.regs.r14;
    regs->r15 = ctx.regs.r15;
#endif

    regs->sp = ctx.regs.sp;
    regs->ip = ctx.regs.ip;

    regs->flags = (regs->flags & ~FIX_EFLAGS) | (ctx.regs.flags & FIX_EFLAGS);

    task_set_blocked_signals(current, ctx.blocked_signals);

    return ctx.regs.ax;
}
