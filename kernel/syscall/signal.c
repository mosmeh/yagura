#include <common/limits.h>
#include <kernel/memory/safe_string.h>
#include <kernel/task/signal.h>
#include <kernel/task/task.h>

long sys_kill(pid_t pid, int sig) {
    if (pid > 0) {
        // Send the signal to the process with the specified pid.
        return signal_send_to_thread_groups(0, pid, sig);
    }
    if (pid == 0) {
        // Send the signal to all processes in the caller's process group.
        return signal_send_to_thread_groups(current->thread_group->pgid, 0,
                                            sig);
    }
    if (pid == -1) {
        // Send the signal to all processes except the calling process.
        return signal_send_to_thread_groups(0, -current->thread_group->tgid,
                                            sig);
    }
    if (pid == INT_MIN)
        return -ESRCH; // -INT_MIN overflows
    // Send the signal to all processes in the specified process group.
    return signal_send_to_thread_groups(-pid, 0, sig);
}

long sys_tkill(pid_t tid, int sig) {
    if (tid <= 0)
        return -EINVAL;
    return signal_send_to_tasks(0, tid, sig);
}

long sys_tgkill(pid_t tgid, pid_t tid, int sig) {
    if (tgid <= 0 || tid <= 0)
        return -EINVAL;
    return signal_send_to_tasks(tgid, tid, sig);
}

NODISCARD static long sigaction(int signum, const struct sigaction* act,
                                struct sigaction* oldact) {
    if (signum <= 0 || NSIG <= signum)
        return -EINVAL;
    switch (signum) {
    case SIGKILL:
    case SIGSTOP:
        return -EINVAL;
    }

    struct sighand* sighand = current->sighand;
    SCOPED_LOCK(sighand, sighand);
    struct sigaction* slot = &sighand->actions[signum - 1];
    if (oldact)
        *oldact = *slot;
    if (act)
        *slot = *act;
    return 0;
}

long sys_signal(int signum, sighandler_t handler) {
    struct sigaction act = {
        .sa_handler = handler,
        .sa_flags = SA_RESETHAND | SA_NODEFER,
    };
    struct sigaction oldact;
    long rc = sigaction(signum, &act, &oldact);
    if (IS_ERR(rc))
        return rc;
    return (long)oldact.sa_handler;
}

long sys_sigaction(int signum, const struct sigaction* user_act,
                   struct sigaction* user_oldact) {
    struct sigaction act;
    if (user_act) {
        if (copy_from_user(&act, user_act, sizeof(struct sigaction)))
            return -EFAULT;
    }
    struct sigaction oldact;
    long rc =
        sigaction(signum, user_act ? &act : NULL, user_oldact ? &oldact : NULL);
    if (IS_ERR(rc))
        return rc;
    if (user_oldact) {
        if (copy_to_user(user_oldact, &oldact, sizeof(struct sigaction)))
            return -EFAULT;
    }
    return 0;
}

long sys_sgetmask(void) { return current->blocked_signals; }

long sys_ssetmask(long newmask) {
    return task_set_blocked_signals(current, newmask);
}

long sys_sigprocmask(int how, const sigset_t* user_set, sigset_t* user_oldset) {
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
        oldset = task_set_blocked_signals(current, set);
    } else {
        oldset = current->blocked_signals;
    }
    if (user_oldset) {
        if (copy_to_user(user_oldset, &oldset, sizeof(sigset_t)))
            return -EFAULT;
    }
    return 0;
}

long sys_pause(void) { return sched_block(NULL, NULL, 0); }

long sys_sigsuspend(const sigset_t* user_mask) {
    sigset_t mask;
    if (copy_from_user(&mask, user_mask, sizeof(sigset_t)))
        return -EFAULT;
    sigset_t old_mask = task_set_blocked_signals(current, mask);
    int rc = sys_pause();
    task_set_blocked_signals(current, old_mask);
    return rc;
}

long sys_sigpending(sigset_t* user_set) {
    sigset_t set = current->pending_signals & current->blocked_signals;
    if (copy_to_user(user_set, &set, sizeof(sigset_t)))
        return -EFAULT;
    return 0;
}
