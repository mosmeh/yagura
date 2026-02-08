#pragma once

#include <kernel/api/signal.h>
#include <sys/types.h>

extern const char* const sys_signame[NSIG];
extern const char* const sys_siglist[NSIG];

int kill(pid_t pid, int sig);
int tgkill(pid_t tgid, pid_t tid, int sig);
int raise(int sig);

sighandler_t signal(int signum, sighandler_t handler);
int sigaction(int signum, const struct sigaction* act,
              struct sigaction* oldact);
int sigprocmask(int how, const sigset_t* set, sigset_t* oldset);
int sigsuspend(const sigset_t* mask);
int sigpending(sigset_t* set);

int sigemptyset(sigset_t* set);
int sigfillset(sigset_t* set);

int sigaddset(sigset_t* set, int signum);
int sigdelset(sigset_t* set, int signum);
int sigorset(sigset_t* dest, const sigset_t* left, const sigset_t* right);
int sigandset(sigset_t* dest, const sigset_t* left, const sigset_t* right);

int sigismember(const sigset_t* set, int signum);
int sigisemptyset(const sigset_t* set);
