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

NODISCARD static int
copy_sigset_from_user_old(sigset_t* dest, const linux_old_sigset_t* user_src) {
    linux_old_sigset_t set;
    if (copy_from_user(&set, user_src, sizeof(linux_old_sigset_t)))
        return -EFAULT;
    sigemptyset(dest);
    sigaddsetmask(dest, set);
    return 0;
}

NODISCARD static int copy_sigset_to_user_old(linux_old_sigset_t* user_dest,
                                             const sigset_t* src) {
    linux_old_sigset_t old_sigset = src->sig[0];
    if (copy_to_user(user_dest, &old_sigset, sizeof(linux_old_sigset_t)))
        return -EFAULT;
    return 0;
}

NODISCARD static int
copy_sigaction_from_user_old(struct sigaction* dest,
                             const struct linux_old_sigaction* user_src) {
    struct linux_old_sigaction act;
    if (copy_from_user(&act, user_src, sizeof(struct linux_old_sigaction)))
        return -EFAULT;
    *dest = (struct sigaction){
        .sa_handler = act.sa_handler,
        .sa_flags = act.sa_flags,
        .sa_restorer = act.sa_restorer,
        .sa_mask = {.sig = {act.sa_mask}},
    };
    return 0;
}

NODISCARD static int
copy_sigaction_to_user_old(struct linux_old_sigaction* user_dest,
                           const struct sigaction* src) {
    struct linux_old_sigaction act = {
        .sa_handler = src->sa_handler,
        .sa_flags = src->sa_flags,
        .sa_restorer = src->sa_restorer,
        .sa_mask = src->sa_mask.sig[0],
    };
    if (copy_to_user(user_dest, &act, sizeof(struct linux_old_sigaction)))
        return -EFAULT;
    return 0;
}

NODISCARD static int sigaction(int signum, const struct sigaction* act,
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
    int rc = sigaction(signum, &act, &oldact);
    if (IS_ERR(rc))
        return rc;
    return (long)oldact.sa_handler;
}

long sys_sigaction(int signum, const struct linux_old_sigaction* user_act,
                   struct linux_old_sigaction* user_oldact) {
    struct sigaction act;
    if (user_act) {
        if (copy_sigaction_from_user_old(&act, user_act))
            return -EFAULT;
    }
    struct sigaction oldact;
    int rc =
        sigaction(signum, user_act ? &act : NULL, user_oldact ? &oldact : NULL);
    if (IS_ERR(rc))
        return rc;
    if (user_oldact) {
        if (copy_sigaction_to_user_old(user_oldact, &oldact))
            return -EFAULT;
    }
    return 0;
}

long sys_rt_sigaction(int signum, const struct sigaction* user_act,
                      struct sigaction* user_oldact, size_t sigsetsize) {
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;

    struct sigaction act;
    if (user_act) {
        if (copy_from_user(&act, user_act, sizeof(struct sigaction)))
            return -EFAULT;
    }
    struct sigaction oldact;
    int rc =
        sigaction(signum, user_act ? &act : NULL, user_oldact ? &oldact : NULL);
    if (IS_ERR(rc))
        return rc;
    if (user_oldact) {
        if (copy_to_user(user_oldact, &oldact, sizeof(struct sigaction)))
            return -EFAULT;
    }

    return 0;
}

long sys_sgetmask(void) { return current->blocked_signals.sig[0]; }

long sys_ssetmask(long newmask) {
    unsigned long old_mask = current->blocked_signals.sig[0];
    sigset_t new_mask;
    sigemptyset(&new_mask);
    sigaddsetmask(&new_mask, newmask);
    task_set_blocked_signals(current, &new_mask);
    return old_mask;
}

NODISCARD static int sigprocmask(int how, const sigset_t* set,
                                 sigset_t* oldset) {
    if (oldset)
        *oldset = current->blocked_signals;
    if (set) {
        sigset_t new_set;
        switch (how) {
        case SIG_BLOCK:
            sigorsets(&new_set, set, &current->blocked_signals);
            break;
        case SIG_UNBLOCK:
            sigandnsets(&new_set, &current->blocked_signals, set);
            break;
        case SIG_SETMASK:
            new_set = *set;
            break;
        default:
            return -EINVAL;
        }
        task_set_blocked_signals(current, &new_set);
    }
    return 0;
}

long sys_sigprocmask(int how, const linux_old_sigset_t* user_set,
                     linux_old_sigset_t* user_oldset) {
    sigset_t set;
    if (user_set) {
        if (copy_sigset_from_user_old(&set, user_set))
            return -EFAULT;
    }
    sigset_t oldset;
    int rc =
        sigprocmask(how, user_set ? &set : NULL, user_oldset ? &oldset : NULL);
    if (IS_ERR(rc))
        return rc;
    if (user_oldset) {
        if (copy_sigset_to_user_old(user_oldset, &oldset))
            return -EFAULT;
    }
    return 0;
}

long sys_rt_sigprocmask(int how, const sigset_t* user_set,
                        sigset_t* user_oldset, size_t sigsetsize) {
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;

    sigset_t set;
    if (user_set) {
        if (copy_from_user(&set, user_set, sizeof(sigset_t)))
            return -EFAULT;
    }
    sigset_t oldset;
    int rc =
        sigprocmask(how, user_set ? &set : NULL, user_oldset ? &oldset : NULL);
    if (IS_ERR(rc))
        return rc;
    if (user_oldset) {
        if (copy_to_user(user_oldset, &oldset, sizeof(sigset_t)))
            return -EFAULT;
    }

    return 0;
}

long sys_pause(void) { return sched_block(NULL, NULL, 0); }

NODISCARD static int sigsuspend(const sigset_t* mask) {
    sigset_t old_mask = current->blocked_signals;
    task_set_blocked_signals(current, mask);
    int rc = sys_pause();
    task_set_blocked_signals(current, &old_mask);
    return rc;
}

long sys_sigsuspend(const linux_old_sigset_t* user_mask) {
    sigset_t mask;
    if (copy_sigset_from_user_old(&mask, user_mask))
        return -EFAULT;
    return sigsuspend(&mask);
}

long sys_rt_sigsuspend(const sigset_t* user_mask, size_t sigsetsize) {
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;
    sigset_t mask;
    if (copy_from_user(&mask, user_mask, sizeof(sigset_t)))
        return -EFAULT;
    return sigsuspend(&mask);
}

static void sigpending(sigset_t* set) {
    {
        SCOPED_LOCK(sighand, current->sighand);
        sigorsets(set, &current->pending_signals,
                  &current->thread_group->pending_signals);
    }
    sigandsets(set, set, &current->blocked_signals);
}

long sys_sigpending(linux_old_sigset_t* user_set) {
    sigset_t set;
    sigpending(&set);
    if (copy_sigset_to_user_old(user_set, &set))
        return -EFAULT;
    return 0;
}

long sys_rt_sigpending(sigset_t* user_set, size_t sigsetsize) {
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;

    sigset_t set;
    sigpending(&set);
    if (copy_to_user(user_set, &set, sizeof(sigset_t)))
        return -EFAULT;
    return 0;
}
