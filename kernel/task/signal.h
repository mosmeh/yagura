#pragma once

#include <common/macros.h>
#include <kernel/api/signal.h>

struct registers;

// Sends a process-directed signal to thread groups matching the given criteria.
// Returns -ESRCH if no matching thread group is found.
NODISCARD int signal_send_to_thread_groups(pid_t pgid, pid_t tgid, int signum);

// Sends a thread-directed signal to the tasks matching the given criteria.
// Returns -ESRCH if no matching task is found.
NODISCARD int signal_send_to_tasks(pid_t tgid, pid_t tid, int signum);

// The matching rules for id are as follows:
// - If id = N > 0: matches tasks with id = N.
// - If id = -N < 0: matches tasks with id != N.
// - If id = 0: matches tasks with any id.

// Returns the signal number that should be handled by the current task,
// or 0 if no signal is pending.
// If out_action is not NULL, it is filled with the sigaction for the signal.
// This function exits the current task if it popped a fatal signal.
NODISCARD int signal_pop(struct sigaction* out_action);

// Handles a signal for the current task.
void signal_handle(struct registers* regs, int signum,
                   const struct sigaction* action);

void sigemptyset(sigset_t*);

int sigaddset(sigset_t*, int signum);
int sigdelset(sigset_t*, int signum);

void sigaddsetmask(sigset_t*, unsigned long mask);
void sigdelsetmask(sigset_t*, unsigned long mask);

void sigandsets(sigset_t* dest, const sigset_t* left, const sigset_t* right);
void sigorsets(sigset_t* dest, const sigset_t* left, const sigset_t* right);
void sigandnsets(sigset_t* dest, const sigset_t* left, const sigset_t* right);

int sigismember(const sigset_t*, int signum);
int sigisemptyset(const sigset_t*);
