#include "private.h"
#include <common/integer.h>
#include <common/string.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/memory/safe_string.h>
#include <kernel/task/task.h>

struct sighand* sighand_create(void) {
    struct sighand* sighand = kmalloc(sizeof(struct sighand));
    if (!sighand)
        return ERR_PTR(-ENOMEM);
    *sighand = (struct sighand){.refcount = REFCOUNT_INIT_ONE};
    return sighand;
}

struct sighand* sighand_clone(struct sighand* sighand) {
    struct sighand* new_sighand = sighand_create();
    if (IS_ERR(ASSERT(new_sighand)))
        return new_sighand;
    SCOPED_LOCK(sighand, sighand);
    memcpy(new_sighand->actions, sighand->actions, sizeof(sighand->actions));
    return new_sighand;
}

void __sighand_destroy(struct sighand* sighand) { kfree(sighand); }

sigset_t task_set_blocked_signals(sigset_t sigset) {
    return atomic_exchange(&current->blocked_signals,
                           sigset & ~(sigmask(SIGKILL) | sigmask(SIGSTOP)));
}

static enum {
    DISP_TERM,
    DISP_IGN,
    DISP_CORE,
    DISP_STOP,
    DISP_CONT,
} default_dispositions[] = {
    [SIGABRT] = DISP_CORE,   [SIGALRM] = DISP_TERM,   [SIGBUS] = DISP_CORE,
    [SIGCHLD] = DISP_IGN,    [SIGCONT] = DISP_CONT,   [SIGFPE] = DISP_CORE,
    [SIGHUP] = DISP_TERM,    [SIGILL] = DISP_CORE,    [SIGINT] = DISP_TERM,
    [SIGIO] = DISP_TERM,     [SIGKILL] = DISP_TERM,   [SIGPIPE] = DISP_TERM,
    [SIGPROF] = DISP_TERM,   [SIGPWR] = DISP_TERM,    [SIGQUIT] = DISP_CORE,
    [SIGSEGV] = DISP_CORE,   [SIGSTKFLT] = DISP_TERM, [SIGSTOP] = DISP_STOP,
    [SIGTSTP] = DISP_STOP,   [SIGSYS] = DISP_CORE,    [SIGTERM] = DISP_TERM,
    [SIGTRAP] = DISP_CORE,   [SIGTTIN] = DISP_STOP,   [SIGTTOU] = DISP_STOP,
    [SIGURG] = DISP_IGN,     [SIGUSR1] = DISP_TERM,   [SIGUSR2] = DISP_TERM,
    [SIGVTALRM] = DISP_TERM, [SIGXCPU] = DISP_CORE,   [SIGXFSZ] = DISP_CORE,
    [SIGWINCH] = DISP_IGN,
};

STATIC_ASSERT(ARRAY_SIZE(default_dispositions) == NSIG);

static void do_send_signal(struct task* task, int signum) {
    if (!task->sighand) {
        // The task is already dead.
        return;
    }

    int default_disposition = default_dispositions[signum];

    sigset_t cleared_signals = sigmask(signum);
    switch (default_disposition) {
    case DISP_CONT:
        cleared_signals |= sigmask(SIGSTOP) | sigmask(SIGTSTP) |
                           sigmask(SIGTTIN) | sigmask(SIGTTOU);
        break;
    case DISP_STOP:
        cleared_signals |= sigmask(SIGCONT);
        break;
    default:
        break;
    }
    task->pending_signals &= ~cleared_signals;

    struct sighand* sighand = task->sighand;
    SCOPED_LOCK(sighand, sighand);
    sighandler_t handler = sighand->actions[signum - 1].sa_handler;
    bool ignored = (handler == SIG_IGN) ||
                   (handler == SIG_DFL && default_disposition == DISP_IGN);
    if (!ignored)
        task->pending_signals |= sigmask(signum);
}

int task_send_signal(pid_t pid, int signum, int flags) {
    ASSERT(pid >= 0);
    unsigned num_group_flags = (bool)(flags & SIGNAL_DEST_ALL_USER_TASKS) +
                               (bool)(flags & SIGNAL_DEST_THREAD_GROUP) +
                               (bool)(flags & SIGNAL_DEST_PROCESS_GROUP);
    ASSERT(num_group_flags <= 1);
    if (signum < 0 || signum >= NSIG)
        return -EINVAL;

    SCOPED_LOCK(spinlock, &all_tasks_lock);

    bool found_dest = false;
    for (struct task* it = all_tasks; it; it = it->all_tasks_next) {
        if (flags & SIGNAL_DEST_ALL_USER_TASKS) {
            if (it->tid <= 1)
                continue;
        } else if (flags & SIGNAL_DEST_THREAD_GROUP) {
            if (it->tgid != pid)
                continue;
        } else if (flags & SIGNAL_DEST_PROCESS_GROUP) {
            if (it->pgid != pid)
                continue;
        } else if (it->tid != pid) {
            continue;
        }
        if (flags & SIGNAL_DEST_EXCLUDE_CURRENT) {
            if (it == current)
                continue;
        }
        found_dest = true;

        if (signum == 0) {
            // signum == 0 is used to check if the task exists.
            continue;
        }

        do_send_signal(it, signum);
    }

    return found_dest ? 0 : -ESRCH;
}

int task_pop_signal(struct sigaction* out_action) {
    struct sighand* sighand = current->sighand;
    spinlock_lock(&sighand->lock);
    for (;;) {
        int signum =
            __builtin_ffs(current->pending_signals & ~current->blocked_signals);
        if (!signum)
            break;
        current->pending_signals &= ~sigmask(signum);

        struct sigaction* action = &sighand->actions[signum - 1];
        if (action->sa_handler == SIG_IGN)
            continue;

        if (action->sa_handler != SIG_DFL) {
            if (out_action)
                *out_action = *action;
            if (action->sa_flags & SA_RESETHAND)
                action->sa_handler = SIG_DFL;
            spinlock_unlock(&sighand->lock);
            return signum;
        }

        switch (default_dispositions[signum]) {
        case DISP_TERM:
        case DISP_CORE:
            spinlock_unlock(&sighand->lock);
            task_terminate(signum);
        case DISP_STOP: {
            spinlock_unlock(&sighand->lock);

            {
                SCOPED_DISABLE_INTERRUPTS();
                current->state = TASK_STOPPED;
                sched_yield();
            }
            // Here we were resumed by SIGCONT.

            spinlock_lock(&sighand->lock);
            break;
        }
        case DISP_CONT:
        case DISP_IGN:
            break;
        default:
            UNREACHABLE();
        }
    }
    spinlock_unlock(&sighand->lock);
    return 0;
}

extern unsigned char signal_trampoline_start[];
extern unsigned char signal_trampoline_end[];

void task_handle_signal(struct registers* regs, int signum,
                        const struct sigaction* action) {
    ASSERT(0 < signum && signum < NSIG);

    struct sigcontext ctx = {
        .regs = *regs,
        .blocked_signals = current->blocked_signals,
    };
    ASSERT((uintptr_t)signal_trampoline_start + sizeof(ctx.trampoline) ==
           (uintptr_t)signal_trampoline_end);
    memcpy(ctx.trampoline, signal_trampoline_start, sizeof(ctx.trampoline));

    uintptr_t esp = ROUND_DOWN(regs->esp, 16);

    // Push the context of the interrupted task
    esp -= sizeof(struct sigcontext);
    struct sigcontext* user_ctx = (struct sigcontext*)esp;
    if (copy_to_user(user_ctx, &ctx, sizeof(struct sigcontext)))
        goto fail;

    // Push the argument of the signal handler
    esp -= sizeof(int);
    if (copy_to_user((void*)esp, &signum, sizeof(int)))
        goto fail;

    uintptr_t trampoline = (action->sa_flags & SA_RESTORER)
                               ? (uintptr_t)action->sa_restorer
                               : (uintptr_t)user_ctx->trampoline;

    // Push the return address of the signal handler
    esp -= sizeof(uintptr_t);
    if (copy_to_user((void*)esp, &trampoline, sizeof(uintptr_t)))
        goto fail;

    regs->esp = esp;
    regs->eip = (uintptr_t)action->sa_handler;

    sigset_t new_blocked = current->blocked_signals | action->sa_mask;
    if (!(action->sa_flags & SA_NODEFER))
        new_blocked |= sigmask(signum);
    task_set_blocked_signals(new_blocked);

    return;

fail:
    task_crash(SIGSEGV);
}
