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

struct sigcontext {
    sigset_t blocked_signals;
    struct registers regs;
};

struct sigframe {
    uintptr_t restorer;
    int signum;
    struct sigcontext ctx;
#ifdef ARCH_I386
    unsigned char trampoline[8];
#endif
#ifdef ARCH_X86_64
    unsigned char trampoline[10];
#endif
};

int arch_handle_signal(struct registers* regs, int signum,
                       const struct sigaction* action) {
    struct sigframe frame = {.signum = signum,
                             .ctx = {
                                 .regs = *regs,
                                 .blocked_signals = current->blocked_signals,
                             }};
    ASSERT((uintptr_t)signal_trampoline_start + sizeof(frame.trampoline) ==
           (uintptr_t)signal_trampoline_end);
    memcpy(frame.trampoline, signal_trampoline_start, sizeof(frame.trampoline));

#ifdef ARCH_X86_64
    regs->sp -= 128; // Skip red zone
#endif

    regs->sp -= sizeof(struct sigframe);

#ifdef ARCH_I386
    regs->sp = ROUND_DOWN(regs->sp + 4, 16) - 4;
#endif
#ifdef ARCH_X86_64
    regs->sp = ROUND_DOWN(regs->sp, 16) - 8;
#endif

    struct sigframe* user_frame = (struct sigframe*)regs->sp;
    frame.restorer = (action->sa_flags & SA_RESTORER)
                         ? (uintptr_t)action->sa_restorer
                         : (uintptr_t)user_frame->trampoline;
    if (copy_to_user(user_frame, &frame, sizeof(struct sigframe)))
        return -EFAULT;

    regs->ip = (uintptr_t)action->sa_handler;
    regs->cs = USER_CS | 3;

#ifdef ARCH_I386
    regs->ax = signum;
    regs->cx = regs->dx = 0;
    regs->ss = regs->ds = regs->es = USER_DS | 3;
#endif
#ifdef ARCH_X86_64
    regs->di = signum;
    regs->ax = 0;
#endif

    return 0;
}

static bool is_valid_segment(unsigned long seg) {
    unsigned long last_seg = (NUM_GDT_ENTRIES - 1) * 8UL;
    return seg <= (last_seg | 3);
}

NODISCARD
static int copy_sigcontext_from_user(struct sigcontext* dest,
                                     const struct sigcontext* user_src) {
    if (copy_from_user(dest, user_src, sizeof(struct sigcontext)))
        return -EFAULT;
    if (!is_valid_segment(dest->regs.ss) || !is_valid_segment(dest->regs.cs) ||
        !is_valid_segment(dest->regs.ds) || !is_valid_segment(dest->regs.es) ||
        !is_valid_segment(dest->regs.fs) || !is_valid_segment(dest->regs.gs))
        return -EFAULT;
    return 0;
}

static unsigned long fix_segment(unsigned long seg) {
    // Ensure the RPL is 3 for non-null segments
    if (seg & ~3)
        seg |= 3;
    return seg;
}

#define FIX_EFLAGS                                                             \
    (X86_EFLAGS_AC | X86_EFLAGS_OF | X86_EFLAGS_DF | X86_EFLAGS_TF |           \
     X86_EFLAGS_SF | X86_EFLAGS_ZF | X86_EFLAGS_AF | X86_EFLAGS_PF |           \
     X86_EFLAGS_CF | X86_EFLAGS_RF)

long sys_sigreturn(struct registers* regs) {
    struct sigcontext ctx;
    if (copy_sigcontext_from_user(&ctx, (const void*)regs->sp))
        task_crash(SIGSEGV);

    regs->ss = ctx.regs.ss | 3;
    regs->cs = ctx.regs.cs | 3;
    regs->ds = fix_segment(ctx.regs.ds);
    regs->es = fix_segment(ctx.regs.es);
    regs->fs = fix_segment(ctx.regs.fs);
    regs->gs = fix_segment(ctx.regs.gs);

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
