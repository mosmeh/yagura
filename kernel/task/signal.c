#include "private.h"
#include <common/integer.h>
#include <common/limits.h>
#include <common/string.h>
#include <kernel/interrupts.h>
#include <kernel/memory/safe_string.h>
#include <kernel/task/task.h>

static struct slab sighand_slab;

void task_signal_init(void) {
    slab_init(&sighand_slab, "sighand", sizeof(struct sighand));
}

struct sighand* sighand_create(void) {
    struct sighand* sighand = slab_alloc(&sighand_slab);
    if (IS_ERR(sighand))
        return sighand;
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

void __sighand_destroy(struct sighand* sighand) {
    slab_free(&sighand_slab, sighand);
}

sigset_t task_get_pending_signals(struct task* task) {
    return (task->pending_signals | task->thread_group->pending_signals) &
           ~task->blocked_signals;
}

sigset_t task_set_blocked_signals(struct task* task, sigset_t sigset) {
    return atomic_exchange(&task->blocked_signals,
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

static void send_signal_to_task(struct task* task, int signum,
                                bool process_directed) {
    int default_disposition = default_dispositions[signum];

    // SIGCONT clears stop signals, and stop signals clear SIGCONT.
    // This takes effect even if the signal is ignored.
    sigset_t cleared_signals = 0;
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
    if (cleared_signals) {
        task->thread_group->pending_signals &= ~cleared_signals;
        task->pending_signals &= ~cleared_signals;
    }

    sigset_t mask = sigmask(signum);

    if (task->blocked_signals & mask) {
        // Signal handlers may be changed while the signal is blocked,
        // so this signal should not be ignored.
    } else {
        struct sighand* sighand = task->sighand;
        SCOPED_LOCK(sighand, sighand);
        sighandler_t handler = sighand->actions[signum - 1].sa_handler;
        if (task->thread_group->tgid == 1 && handler == SIG_DFL) {
            // Signals can be sent to the init process only when
            // it has explicitly installed handlers.
            return;
        }
        if (handler == SIG_IGN ||
            (handler == SIG_DFL && default_disposition == DISP_IGN))
            return;
    }

    if (process_directed)
        task->thread_group->pending_signals |= mask;
    else
        task->pending_signals |= mask;
}

int signal_send_to_thread_groups(pid_t pgid, pid_t tgid, int signum) {
    if (pgid == INT_MIN || tgid == INT_MIN)
        return -EINVAL; // -INT_MIN overflows
    if (signum < 0 || signum >= NSIG)
        return -EINVAL;

    SCOPED_LOCK(spinlock, &tasks_lock);

    bool found_task = false;
    for (struct task* it = tasks; it; it = it->tasks_next) {
        struct thread_group* tg = it->thread_group;
        if (pgid > 0) {
            if (tg->pgid != pgid)
                continue;
        } else if (pgid < 0) {
            if (tg->pgid == -pgid)
                continue;
        }
        if (tgid > 0) {
            if (tg->tgid != tgid)
                continue;
        } else if (tgid < 0) {
            if (tg->tgid == -tgid)
                continue;
        }
        found_task = true;

        if (signum == 0) {
            // signum == 0 is used to check if the task exists.
            continue;
        }

        send_signal_to_task(it, signum, true);
    }

    return found_task ? 0 : -ESRCH;
}

int signal_send_to_tasks(pid_t tgid, pid_t tid, int signum) {
    if (tgid == INT_MIN || tid == INT_MIN)
        return -EINVAL; // -INT_MIN overflows
    if (signum < 0 || signum >= NSIG)
        return -EINVAL;

    SCOPED_LOCK(spinlock, &tasks_lock);

    bool found_task = false;
    for (struct task* it = tasks; it; it = it->tasks_next) {
        if (tgid > 0) {
            if (it->thread_group->tgid != tgid)
                continue;
        } else if (tgid < 0) {
            if (it->thread_group->tgid == -tgid)
                continue;
        }
        if (tid > 0) {
            if (it->tid != tid)
                continue;
        } else if (tid < 0) {
            if (it->tid == -tid)
                continue;
        }
        found_task = true;

        if (signum == 0) {
            // signum == 0 is used to check if the task exists.
            continue;
        }

        send_signal_to_task(it, signum, false);
    }

    return found_task ? 0 : -ESRCH;
}

static int pop_one_signal(void) {
    int signum =
        __builtin_ffs(current->pending_signals & ~current->blocked_signals);
    if (signum) {
        current->pending_signals &= ~sigmask(signum);
        return signum;
    }

    struct thread_group* tg = current->thread_group;
    for (;;) {
        sigset_t pending = tg->pending_signals;
        int signum = __builtin_ffs(pending & ~current->blocked_signals);
        if (!signum)
            break;
        sigset_t new_pending = pending & ~sigmask(signum);
        if (atomic_compare_exchange_weak(&tg->pending_signals, &pending,
                                         new_pending))
            return signum;
    }

    return 0;
}

int signal_pop(struct sigaction* out_action) {
    struct sighand* sighand = current->sighand;
    spinlock_lock(&sighand->lock);
    for (;;) {
        int signum = pop_one_signal();
        if (!signum)
            break;

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

void signal_handle(struct registers* regs, int signum,
                   const struct sigaction* action) {
    ASSERT(0 < signum && signum < NSIG);

    int rc = arch_handle_signal(regs, signum, action);
    if (IS_ERR(rc))
        task_crash(SIGSEGV);

    sigset_t new_blocked = current->blocked_signals | action->sa_mask;
    if (!(action->sa_flags & SA_NODEFER))
        new_blocked |= sigmask(signum);
    task_set_blocked_signals(current, new_blocked);
}
