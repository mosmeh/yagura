#pragma once

#include <common/integer.h>
#include <common/limits.h>
#include <kernel/api/signal.h>
#include <kernel/api/sys/limits.h>
#include <kernel/arch/context.h>
#include <kernel/cpu.h>
#include <kernel/fs/fs.h>
#include <kernel/sched.h>
#include <kernel/system.h>

enum {
    TASK_RUNNING,
    TASK_UNINTERRUPTIBLE,
    TASK_INTERRUPTIBLE,
    TASK_STOPPED,
    TASK_DEAD,
};

struct task {
    pid_t tid;

    _Atomic(unsigned int) state;
    int exit_status;

    char comm[16];

    _Atomic(struct vm*) vm;
    uintptr_t kernel_stack_base, kernel_stack_top;
    uintptr_t arg_start, arg_end, env_start, env_end;

    struct fs* fs;
    struct files* files;

    struct sighand* sighand;
    sigset_t pending_signals;
    sigset_t blocked_signals;

    unblock_fn unblock;
    void* block_data;
    bool interrupted;

    struct thread_group* thread_group;

    _Atomic(size_t) user_ticks;
    _Atomic(size_t) kernel_ticks;

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

static inline struct task* task_get_current(void) {
    struct task* task =
        (void*)arch_cpu_read(offsetof(struct cpu, current_task));
    ASSERT(task);
    return task;
}

struct task* task_create(const char* comm, void (*entry_point)(void));
struct task* task_clone(const struct task*, unsigned flags);
NODISCARD pid_t task_spawn(const char* comm, void (*entry_point)(void));

DEFINE_LOCKED(task, struct task*, mutex, lock)

void __task_destroy(struct task*);
DEFINE_REFCOUNTED_BASE(task, struct task*, refcount, __task_destroy)

pid_t task_generate_next_tid(void);
struct task* task_find_by_tid(pid_t);

_Noreturn void task_exit(int status);
_Noreturn void task_exit_thread_group(int status);
_Noreturn void task_crash(int signum);

struct fs {
    struct path* root;
    struct path* cwd;
    _Atomic(mode_t) umask;
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
    unsigned long closed_on_exec[DIV_CEIL(OPEN_MAX, ULONG_WIDTH)];
    struct mutex lock;
    refcount_t refcount;
};

struct files* files_clone(struct files*);

DEFINE_LOCKED(files, struct files*, mutex, lock)

void __files_destroy(struct files*);
DEFINE_REFCOUNTED_BASE(files, struct files*, refcount, __files_destroy)

// Allocates lowest-numbered file descriptor >= min_fd
// that is not already used, and sets it to the given file.
// Flags are the file descriptor flags (FD_*).
NODISCARD int files_alloc_fd(struct files*, int min_fd, struct file*,
                             int flags);

// Sets the file at given fd to the given file.
// If the fd is already used, replaces and frees the old file.
// Flags are the file descriptor flags (FD_*).
NODISCARD int files_set_file(struct files*, int fd, struct file*, int flags);

int files_free_fd(struct files*, int fd);

struct file* files_ref_file(struct files*, int fd);

// Gets the file descriptor flags (FD_*) for the given fd.
NODISCARD int files_get_flags(struct files*, int fd);

// Sets the file descriptor flags (FD_*) for the given fd.
NODISCARD int files_set_flags(struct files*, int fd, int flags);

// Closes all file descriptors with FD_CLOEXEC flag set.
NODISCARD int files_close_on_exec(struct files*);

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
    _Atomic(size_t) num_running_tasks;
    sigset_t pending_signals;
    int exit_signal;
    refcount_t refcount;
};

struct thread_group* thread_group_create(void);

void __thread_group_destroy(struct thread_group*);
DEFINE_REFCOUNTED_BASE(thread_group, struct thread_group*, refcount,
                       __thread_group_destroy)

// Returns the set of pending signals for the current task,
// excluding blocked signals.
void task_get_pending_signals(struct task*, sigset_t* out_set);

void task_set_blocked_signals(struct task*, const sigset_t*);

NODISCARD int clone_user_task(struct registers* regs, unsigned long flags,
                              void* user_stack, pid_t* user_parent_tid,
                              pid_t* user_child_tid, void* user_tls);
