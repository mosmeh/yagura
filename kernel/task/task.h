#pragma once

#include <kernel/api/signal.h>
#include <kernel/api/sys/limits.h>
#include <kernel/arch/context.h>
#include <kernel/fs/fs.h>
#include <kernel/sched.h>
#include <kernel/system.h>
#include <stdnoreturn.h>

enum {
    TASK_RUNNING,
    TASK_UNINTERRUPTIBLE,
    TASK_INTERRUPTIBLE,
    TASK_STOPPED,
    TASK_DEAD,
};

struct task {
    pid_t tid;

    atomic_uint state;
    int exit_status;

    char comm[16];

    _Atomic(struct vm*) vm;
    uintptr_t kernel_stack_base, kernel_stack_top;
    uintptr_t arg_start, arg_end, env_start, env_end;

    struct fs* fs;
    struct files* files;

    struct sighand* sighand;
    _Atomic(sigset_t) pending_signals;
    _Atomic(sigset_t) blocked_signals;

    unblock_fn unblock;
    void* block_data;
    bool interrupted;

    struct thread_group* thread_group;

    atomic_size_t user_ticks;
    atomic_size_t kernel_ticks;

    struct task* tasks_next; // global tasks list
    struct task* ready_queue_next;
    struct task* blocked_next;

    struct arch_task arch;

    struct mutex lock;
    refcount_t refcount;
};

extern struct task* tasks;
extern struct spinlock tasks_lock;

void task_init(void);

#define current task_get_current()
struct task* task_get_current(void);

struct task* task_create(const char* comm, void (*entry_point)(void));
struct task* task_clone(const struct task*, unsigned flags);
pid_t task_spawn(const char* comm, void (*entry_point)(void));

DEFINE_LOCKED(task, struct task*, mutex, lock)

void __task_destroy(struct task*);
DEFINE_REFCOUNTED_BASE(task, struct task*, refcount, __task_destroy)

pid_t task_generate_next_tid(void);
struct task* task_find_by_tid(pid_t);

noreturn void task_exit(int status);
noreturn void task_exit_thread_group(int status);
noreturn void task_crash(int signum);

struct fs {
    struct path* root;
    struct path* cwd;
    struct mutex lock;
    refcount_t refcount;
};

struct fs* fs_clone(struct fs*);

DEFINE_LOCKED(fs, struct fs*, mutex, lock)

void __fs_destroy(struct fs*);
DEFINE_REFCOUNTED_BASE(fs, struct fs*, refcount, __fs_destroy)

NODISCARD int fs_chroot(struct fs*, struct path*);
NODISCARD int fs_chdir(struct fs*, struct path*);

struct files {
    struct file* entries[OPEN_MAX];
    struct mutex lock;
    refcount_t refcount;
};

struct files* files_clone(struct files*);

DEFINE_LOCKED(files, struct files*, mutex, lock)

void __files_destroy(struct files*);
DEFINE_REFCOUNTED_BASE(files, struct files*, refcount, __files_destroy)

// If fd >= 0, allocates given file descriptor. If it is already used,
// replacing and freeing the old file.
// If fd < 0, allocates lowest-numbered file descriptor that was unused.
NODISCARD int files_alloc_fd(struct files*, int fd, struct file*);

int files_free_fd(struct files*, int fd);

struct file* files_ref_file(struct files*, int fd);

struct sighand {
    struct sigaction actions[NSIG - 1];
    struct spinlock lock;
    refcount_t refcount;
};

struct sighand* sighand_clone(struct sighand*);

DEFINE_LOCKED(sighand, struct sighand*, spinlock, lock)

void __sighand_destroy(struct sighand*);
DEFINE_REFCOUNTED_BASE(sighand, struct sighand*, refcount, __sighand_destroy)

struct thread_group {
    pid_t tgid;
    _Atomic(pid_t) pgid, ppid;
    atomic_size_t num_running_tasks;
    _Atomic(sigset_t) pending_signals;
    int exit_signal;
    refcount_t refcount;
};

struct thread_group* thread_group_create(void);

void __thread_group_destroy(struct thread_group*);
DEFINE_REFCOUNTED_BASE(thread_group, struct thread_group*, refcount,
                       __thread_group_destroy)

// Returns the set of pending signals for the current task,
// excluding blocked signals.
sigset_t task_get_pending_signals(struct task*);

// Returns the previous blocked signal set.
sigset_t task_set_blocked_signals(struct task*, sigset_t);

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
