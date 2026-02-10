#include "private.h"
#include <common/integer.h>
#include <common/limits.h>
#include <common/string.h>
#include <kernel/api/signal.h>
#include <kernel/interrupts.h>
#include <kernel/memory/safe_string.h>
#include <kernel/task/signal.h>
#include <kernel/task/task.h>

static struct slab sighand_slab;

void task_signal_init(void) {
    slab_init(&sighand_slab, "sighand", sizeof(struct sighand));
}

struct sighand* sighand_create(void) {
    struct sighand* sighand = slab_alloc(&sighand_slab);
    if (IS_ERR(ASSERT(sighand)))
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

void task_get_pending_signals(struct task* task, sigset_t* out_set) {
    SCOPED_LOCK(sighand, task->sighand);
    for (size_t i = 0; i < ARRAY_SIZE(out_set->sig); ++i)
        out_set->sig[i] = (task->pending_signals.sig[i] |
                           task->thread_group->pending_signals.sig[i]) &
                          ~task->blocked_signals.sig[i];
}

void task_set_blocked_signals(struct task* task, const sigset_t* sigset) {
    SCOPED_LOCK(sighand, task->sighand);
    task->blocked_signals = *sigset;
    sigdelsetmask(&task->blocked_signals, sigmask(SIGKILL) | sigmask(SIGSTOP));
}

__extension__ static enum {
    DISP_TERM,
    DISP_IGN,
    DISP_CORE,
    DISP_STOP,
    DISP_CONT,
} default_dispositions[] = {
    [SIGABRT] = DISP_CORE,   [SIGALRM] = DISP_TERM,
    [SIGBUS] = DISP_CORE,    [SIGCHLD] = DISP_IGN,
    [SIGCONT] = DISP_CONT,   [SIGFPE] = DISP_CORE,
    [SIGHUP] = DISP_TERM,    [SIGILL] = DISP_CORE,
    [SIGINT] = DISP_TERM,    [SIGIO] = DISP_TERM,
    [SIGKILL] = DISP_TERM,   [SIGPIPE] = DISP_TERM,
    [SIGPROF] = DISP_TERM,   [SIGPWR] = DISP_TERM,
    [SIGQUIT] = DISP_CORE,   [SIGSEGV] = DISP_CORE,
    [SIGSTKFLT] = DISP_TERM, [SIGSTOP] = DISP_STOP,
    [SIGTSTP] = DISP_STOP,   [SIGSYS] = DISP_CORE,
    [SIGTERM] = DISP_TERM,   [SIGTRAP] = DISP_CORE,
    [SIGTTIN] = DISP_STOP,   [SIGTTOU] = DISP_STOP,
    [SIGURG] = DISP_IGN,     [SIGUSR1] = DISP_TERM,
    [SIGUSR2] = DISP_TERM,   [SIGVTALRM] = DISP_TERM,
    [SIGXCPU] = DISP_CORE,   [SIGXFSZ] = DISP_CORE,
    [SIGWINCH] = DISP_IGN,   [SIGRTMIN... SIGRTMAX] = DISP_TERM,
};

STATIC_ASSERT(ARRAY_SIZE(default_dispositions) == NSIG);

static void clear_pending_signal(struct task* task, int signum) {
    ASSERT(sighand_is_locked_by_current(task->sighand));

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signum);

    sigset_t* tg_pending = &task->thread_group->pending_signals;
    sigandnsets(tg_pending, tg_pending, &set);

    sigandnsets(&task->pending_signals, &task->pending_signals, &set);
}

static void send_signal_to_task(struct task* task, int signum,
                                bool process_directed) {
    SCOPED_LOCK(sighand, task->sighand);

    int default_disposition = default_dispositions[signum];

    // SIGCONT clears stop signals, and stop signals clear SIGCONT.
    // This takes effect even if the signal is ignored.
    switch (default_disposition) {
    case DISP_CONT:
        clear_pending_signal(task, SIGSTOP);
        clear_pending_signal(task, SIGTSTP);
        clear_pending_signal(task, SIGTTIN);
        clear_pending_signal(task, SIGTTOU);
        break;
    case DISP_STOP:
        clear_pending_signal(task, SIGCONT);
        break;
    default:
        break;
    }

    if (sigismember(&task->blocked_signals, signum)) {
        // Signal handlers may be changed while the signal is blocked,
        // so this signal should not be ignored.
    } else {
        struct sighand* sighand = task->sighand;
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
        sigaddset(&task->thread_group->pending_signals, signum);
    else
        sigaddset(&task->pending_signals, signum);
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
    ASSERT(sighand_is_locked_by_current(current->sighand));

    sigset_t pending;
    task_get_pending_signals(current, &pending);
    for (size_t i = 0; i < ARRAY_SIZE(pending.sig); i++) {
        if (!pending.sig[i])
            continue;
        int b = __builtin_ffsl(pending.sig[i]);
        if (!b)
            continue;
        int signum = i * LONG_WIDTH + b;
        clear_pending_signal(current, signum);
        return signum;
    }
    return 0;
}

int signal_pop(struct sigaction* out_action) {
    struct sighand* sighand = current->sighand;
    sighand_lock(sighand);
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
            sighand_unlock(sighand);
            return signum;
        }

        switch (default_dispositions[signum]) {
        case DISP_TERM:
        case DISP_CORE:
            sighand_unlock(sighand);
            task_terminate(signum);
        case DISP_STOP: {
            sighand_unlock(sighand);

            {
                SCOPED_DISABLE_INTERRUPTS();
                current->state = TASK_STOPPED;
                sched_yield();
            }
            // Here we were resumed by SIGCONT.

            sighand_lock(sighand);
            break;
        }
        case DISP_CONT:
        case DISP_IGN:
            break;
        default:
            UNREACHABLE();
        }
    }
    sighand_unlock(sighand);
    return 0;
}

void signal_handle(struct registers* regs, int signum,
                   const struct sigaction* action) {
    ASSERT(0 < signum && signum < NSIG);

    int rc = arch_handle_signal(regs, signum, action);
    if (IS_ERR(rc))
        task_crash(SIGSEGV);

    sigset_t new_blocked;
    sigorsets(&new_blocked, &current->blocked_signals, &action->sa_mask);
    if (!(action->sa_flags & SA_NODEFER))
        sigaddset(&new_blocked, signum);
    task_set_blocked_signals(current, &new_blocked);
}

void sigemptyset(sigset_t* set) {
    for (size_t i = 0; i < ARRAY_SIZE(set->sig); i++)
        set->sig[i] = 0;
}

#define VALIDATE_SIGNUM(signum)                                                \
    if ((signum) <= 0 || NSIG <= (signum))                                     \
        return -EINVAL;

#define INDEX(signum) (((signum) - 1) / LONG_WIDTH)
#define MASK(signum) (1UL << (((signum) - 1) % LONG_WIDTH))

int sigaddset(sigset_t* set, int signum) {
    VALIDATE_SIGNUM(signum);
    set->sig[INDEX(signum)] |= MASK(signum);
    return 0;
}

int sigdelset(sigset_t* set, int signum) {
    VALIDATE_SIGNUM(signum);
    set->sig[INDEX(signum)] &= ~MASK(signum);
    return 0;
}

void sigaddsetmask(sigset_t* set, unsigned long mask) { set->sig[0] |= mask; }

void sigdelsetmask(sigset_t* set, unsigned long mask) { set->sig[0] &= ~mask; }

void sigandsets(sigset_t* dest, const sigset_t* left, const sigset_t* right) {
    for (size_t i = 0; i < ARRAY_SIZE(dest->sig); i++)
        dest->sig[i] = left->sig[i] & right->sig[i];
}

void sigorsets(sigset_t* dest, const sigset_t* left, const sigset_t* right) {
    for (size_t i = 0; i < ARRAY_SIZE(dest->sig); i++)
        dest->sig[i] = left->sig[i] | right->sig[i];
}

void sigandnsets(sigset_t* dest, const sigset_t* left, const sigset_t* right) {
    for (size_t i = 0; i < ARRAY_SIZE(dest->sig); i++)
        dest->sig[i] = left->sig[i] & ~right->sig[i];
}

int sigismember(const sigset_t* set, int signum) {
    VALIDATE_SIGNUM(signum);
    return set->sig[INDEX(signum)] & MASK(signum);
}

int sigisemptyset(const sigset_t* set) {
    for (size_t i = 0; i < ARRAY_SIZE(set->sig); i++) {
        if (set->sig[i])
            return 0;
    }
    return 1;
}
