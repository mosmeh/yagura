#include "private.h"
#include <common/macros.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

int kill(pid_t pid, int sig) {
    return __syscall_return(SYSCALL2(kill, pid, sig));
}

int tgkill(pid_t tgid, pid_t tid, int sig) {
    return __syscall_return(SYSCALL3(tgkill, tgid, tid, sig));
}

int raise(int sig) { return __syscall_return(SYSCALL2(tkill, gettid(), sig)); }

sighandler_t signal(int signum, sighandler_t handler) {
    struct sigaction act = {
        .sa_handler = handler,
        .sa_flags = SA_RESTART,
    };
    struct sigaction oldact;
    if (sigaction(signum, &act, &oldact) < 0)
        return SIG_ERR;
    return oldact.sa_handler;
}

void __sa_restorer(void);

int sigaction(int signum, const struct sigaction* act,
              struct sigaction* oldact) {
    struct sigaction sa;
    if (act) {
        sa = *act;
        sa.sa_flags |= SA_RESTORER;
        sa.sa_restorer = __sa_restorer;
    }
    return __syscall_return(SYSCALL4(rt_sigaction, signum, act ? &sa : NULL,
                                     oldact, sizeof(sigset_t)));
}

int sigprocmask(int how, const sigset_t* set, sigset_t* oldset) {
    return __syscall_return(
        SYSCALL4(rt_sigprocmask, how, set, oldset, sizeof(sigset_t)));
}

int sigsuspend(const sigset_t* mask) {
    return __syscall_return(SYSCALL2(rt_sigsuspend, mask, sizeof(sigset_t)));
}

int sigpending(sigset_t* set) {
    return __syscall_return(SYSCALL2(rt_sigpending, set, sizeof(sigset_t)));
}

int sigemptyset(sigset_t* set) {
    for (size_t i = 0; i < ARRAY_SIZE(set->sig); i++)
        set->sig[i] = 0;
    return 0;
}

int sigfillset(sigset_t* set) {
    for (size_t i = 0; i < ARRAY_SIZE(set->sig); i++)
        set->sig[i] = ULONG_MAX;
    return 0;
}

#define VALIDATE_SIGNUM(signum)                                                \
    if ((signum) <= 0 || NSIG <= (signum)) {                                   \
        errno = EINVAL;                                                        \
        return -1;                                                             \
    }

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

int sigorset(sigset_t* dest, const sigset_t* left, const sigset_t* right) {
    for (size_t i = 0; i < ARRAY_SIZE(dest->sig); i++)
        dest->sig[i] = left->sig[i] | right->sig[i];
    return 0;
}

int sigandset(sigset_t* dest, const sigset_t* left, const sigset_t* right) {
    for (size_t i = 0; i < ARRAY_SIZE(dest->sig); i++)
        dest->sig[i] = left->sig[i] & right->sig[i];
    return 0;
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
