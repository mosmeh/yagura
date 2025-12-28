#include <kernel/api/asm/processor-flags.h>
#include <kernel/api/errno.h>
#include <kernel/fs/path.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task.h>

int sys_kill(pid_t pid, int sig) {
    if (pid > 0)
        return task_send_signal(pid, sig, 0);
    if (pid == 0)
        return task_send_signal(current->pgid, sig, SIGNAL_DEST_PROCESS_GROUP);
    if (pid == -1)
        return task_send_signal(
            0, sig, SIGNAL_DEST_ALL_USER_TASKS | SIGNAL_DEST_EXCLUDE_CURRENT);
    return task_send_signal(-pid, sig, SIGNAL_DEST_PROCESS_GROUP);
}

int sys_sigaction(int signum, const struct sigaction* user_act,
                  struct sigaction* user_oldact) {
    if (signum <= 0 || NSIG <= signum)
        return -EINVAL;
    switch (signum) {
    case SIGKILL:
    case SIGSTOP:
        return -EINVAL;
    }

    struct sigaction act;
    if (user_act) {
        if (copy_from_user(&act, user_act, sizeof(struct sigaction)))
            return -EFAULT;
        if ((!(act.sa_flags & SA_RESTORER) || !act.sa_restorer))
            return -EFAULT;
    }

    struct sighand* sighand = current->sighand;
    SCOPED_LOCK(sighand, sighand);
    struct sigaction* slot = &sighand->actions[signum - 1];
    if (user_oldact) {
        if (copy_to_user(user_oldact, slot, sizeof(struct sigaction)))
            return -EFAULT;
    }
    if (user_act)
        *slot = act;
    return 0;
}

int sys_sigprocmask(int how, const sigset_t* user_set, sigset_t* user_oldset) {
    sigset_t oldset;
    if (user_set) {
        sigset_t set;
        if (copy_from_user(&set, user_set, sizeof(sigset_t)))
            return -EFAULT;
        switch (how) {
        case SIG_BLOCK:
            set |= current->blocked_signals;
            break;
        case SIG_UNBLOCK:
            set = current->blocked_signals & ~set;
            break;
        case SIG_SETMASK:
            break;
        default:
            return -EINVAL;
        }
        oldset = task_set_blocked_signals(set);
    } else {
        oldset = current->blocked_signals;
    }
    if (user_oldset) {
        if (copy_to_user(user_oldset, &oldset, sizeof(sigset_t)))
            return -EFAULT;
    }
    return 0;
}

int sys_pause(void) { return sched_block(NULL, NULL, 0); }

int sys_sigsuspend(const sigset_t* user_mask) {
    sigset_t mask;
    if (copy_from_user(&mask, user_mask, sizeof(sigset_t)))
        return -EFAULT;
    sigset_t old_mask = task_set_blocked_signals(mask);
    int rc = sys_pause();
    task_set_blocked_signals(old_mask);
    return rc;
}

int sys_sigpending(sigset_t* user_set) {
    sigset_t set = current->pending_signals & current->blocked_signals;
    if (copy_to_user(user_set, &set, sizeof(sigset_t)))
        return -EFAULT;
    return 0;
}

#define FIX_EFLAGS                                                             \
    (X86_EFLAGS_AC | X86_EFLAGS_OF | X86_EFLAGS_DF | X86_EFLAGS_TF |           \
     X86_EFLAGS_SF | X86_EFLAGS_ZF | X86_EFLAGS_AF | X86_EFLAGS_PF |           \
     X86_EFLAGS_CF | X86_EFLAGS_RF)

int sys_sigreturn(struct registers* regs) {
    struct sigcontext ctx;
    if (copy_from_user(&ctx, (void*)regs->esp, sizeof(struct sigcontext)))
        task_crash(SIGSEGV);

    regs->ss = ctx.regs.ss | 3;
    regs->cs = ctx.regs.cs | 3;
    regs->ds = ctx.regs.ds;
    regs->es = ctx.regs.es;
    regs->fs = ctx.regs.fs;
    regs->gs = ctx.regs.gs;

    regs->ebx = ctx.regs.ebx;
    regs->ecx = ctx.regs.ecx;
    regs->edx = ctx.regs.edx;
    regs->esi = ctx.regs.esi;
    regs->edi = ctx.regs.edi;
    regs->ebp = ctx.regs.ebp;
    regs->esp = ctx.regs.esp;
    regs->eip = ctx.regs.eip;

    regs->eflags =
        (regs->eflags & ~FIX_EFLAGS) | (ctx.regs.eflags & FIX_EFLAGS);

    task_set_blocked_signals(ctx.blocked_signals);

    return ctx.regs.eax;
}
