#include "signal.h"
#include <private.h>
#include <unistd.h>

int kill(pid_t pid, int sig) {
    RETURN_WITH_ERRNO(int, SYSCALL2(kill, pid, sig));
}

int raise(int sig) { return kill(gettid(), sig); }

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
    struct sigaction sa = *act;
    sa.sa_flags |= SA_RESTORER;
    sa.sa_restorer = __sa_restorer;
    RETURN_WITH_ERRNO(int, SYSCALL3(sigaction, signum, &sa, oldact));
}

int sigprocmask(int how, const sigset_t* set, sigset_t* oldset) {
    RETURN_WITH_ERRNO(int, SYSCALL3(sigprocmask, how, set, oldset));
}

int sigsuspend(const sigset_t* mask) {
    RETURN_WITH_ERRNO(int, SYSCALL1(sigsuspend, mask));
}

int sigpending(sigset_t* set) {
    RETURN_WITH_ERRNO(int, SYSCALL1(sigpending, set));
}

int sigemptyset(sigset_t* set) {
    *set = 0;
    return 0;
}

int sigfillset(sigset_t* set) {
    *set = ~0;
    return 0;
}

#define VALIDATE_SIGNUM(signum)                                                \
    if ((signum) <= 0 || NSIG <= (signum)) {                                   \
        errno = EINVAL;                                                        \
        return -1;                                                             \
    }

int sigaddset(sigset_t* set, int signum) {
    VALIDATE_SIGNUM(signum);
    *set |= sigmask(signum);
    return 0;
}

int sigdelset(sigset_t* set, int signum) {
    VALIDATE_SIGNUM(signum);
    *set &= ~sigmask(signum);
    return 0;
}

int sigorset(sigset_t* dest, const sigset_t* left, const sigset_t* right) {
    *dest = *left | *right;
    return 0;
}

int sigandset(sigset_t* dest, const sigset_t* left, const sigset_t* right) {
    *dest = *left & *right;
    return 0;
}

int sigismember(const sigset_t* set, int signum) {
    VALIDATE_SIGNUM(signum);
    return (*set & sigmask(signum)) != 0;
}

int sigisemptyset(const sigset_t* set) { return !*set; }
