#pragma once

#include <kernel/api/sys/types.h>

typedef void (*sighandler_t)(int);
typedef uint32_t sigset_t;

#define sigmask(sig) (1U << ((sig) - 1))

#define SIG_ERR ((sighandler_t)(-1)) // Error return.
#define SIG_DFL ((sighandler_t)0)    // Default action.
#define SIG_IGN ((sighandler_t)1)    // Ignore signal.

#define SA_RESTORER 0x04000000

// Restart syscall on signal return.
#define SA_RESTART 0x10000000

// Don't automatically block the signal when its handler is being executed.
#define SA_NODEFER 0x40000000

// Reset to SIG_DFL on entry to handler.
#define SA_RESETHAND 0x80000000

struct sigaction {
    sighandler_t sa_handler;
    sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
};

#define SIG_BLOCK 0   // Block signals.
#define SIG_UNBLOCK 1 // Unblock signals.
#define SIG_SETMASK 2 // Set the set of blocked signals.

#define ENUMERATE_SIGNALS(F)                                                   \
    F(SIGINVALID, "Invalid signal")                                            \
    F(SIGHUP, "Hangup")                                                        \
    F(SIGINT, "Interrupt")                                                     \
    F(SIGQUIT, "Quit")                                                         \
    F(SIGILL, "Illegal instruction")                                           \
    F(SIGTRAP, "Trace/breakpoint trap")                                        \
    F(SIGABRT, "Aborted")                                                      \
    F(SIGBUS, "Bus error")                                                     \
    F(SIGFPE, "Floating point exception")                                      \
    F(SIGKILL, "Killed")                                                       \
    F(SIGUSR1, "User defined signal 1")                                        \
    F(SIGSEGV, "Segmentation violation")                                       \
    F(SIGUSR2, "User defined signal 2")                                        \
    F(SIGPIPE, "Broken pipe")                                                  \
    F(SIGALRM, "Alarm clock")                                                  \
    F(SIGTERM, "Terminated")                                                   \
    F(SIGSTKFLT, "Stack fault")                                                \
    F(SIGCHLD, "Child exited")                                                 \
    F(SIGCONT, "Continued")                                                    \
    F(SIGSTOP, "Stopped (signal)")                                             \
    F(SIGTSTP, "Stopped")                                                      \
    F(SIGTTIN, "Stopped (tty input)")                                          \
    F(SIGTTOU, "Stopped (tty output)")                                         \
    F(SIGURG, "Urgent I/O condition")                                          \
    F(SIGXCPU, "CPU time limit exceeded")                                      \
    F(SIGXFSZ, "File size limit exceeded")                                     \
    F(SIGVTALRM, "Virtual timer expired")                                      \
    F(SIGPROF, "Profiling timer expired")                                      \
    F(SIGWINCH, "Window changed")                                              \
    F(SIGIO, "I/O possible")                                                   \
    F(SIGPWR, "Power failure")                                                 \
    F(SIGSYS, "Bad system call")

#define ENUM_ITEM(I, MSG) I,
enum { ENUMERATE_SIGNALS(ENUM_ITEM) NSIG };
#undef ENUM_ITEM
