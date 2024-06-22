#pragma once

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
