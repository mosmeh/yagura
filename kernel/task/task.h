#pragma once

#include <kernel/memory/memory.h>

#define KERNEL_STACK_SIZE (PAGE_SIZE * 4)

#ifndef __ASSEMBLER__

#include <common/integer.h>
#include <common/limits.h>
#include <kernel/api/signal.h>
#include <kernel/api/sys/limits.h>
#include <kernel/arch/context.h>
#include <kernel/cpu.h>
#include <kernel/sched.h>
#include <kernel/system.h>
#include <kernel/task/workqueue.h>

#define TASK_RUNNING 0x0         // Running or runnable
#define TASK_INTERRUPTIBLE 0x1   // Sleeping and can be woken by a signal
#define TASK_UNINTERRUPTIBLE 0x2 // Sleeping and cannot be woken by a signal
#define TASK_STOPPED 0x4         // Stopped and can be woken by SIGCONT
#define TASK_DEAD 0x80           // Exiting or exited

#define TASK_NOLOAD 0x400 // Task should not be counted in load average

#define TASK_IDLE (TASK_UNINTERRUPTIBLE | TASK_NOLOAD)

struct task {
    pid_t tid;

    _Atomic(unsigned int) state;
    _Atomic(int) exit_status;

    char comm[16];

    struct vm* vm;
    uintptr_t kernel_stack_base, kernel_stack_top;
    uintptr_t arg_start, arg_end, env_start, env_end;

    struct fs_env* fs_env;
    struct fd_table* fd_table;

    struct sighand* sighand;
    sigset_t pending_signals;
    sigset_t blocked_signals;

    struct wait_state wait_state;

    struct thread_group* thread_group;

    _Atomic(size_t) user_ticks;
    _Atomic(size_t) kernel_ticks;

    struct task* tasks_next; // global tasks list
    struct task* ready_queue_next;
    struct task* blocked_next;

    struct arch_task arch;

    struct work destroy_work;

    struct mutex lock;
    refcount_t refcount;
};

extern struct task* tasks;
extern struct spinlock tasks_lock;

void task_early_init(void);
void task_late_init(void);

#define current task_get_current()

static inline struct task* task_get_current(void) {
    return ASSERT_PTR((void*)arch_cpu_read(offsetof(struct cpu, current_task)));
}

struct task* task_create(const char* comm, void (*entry_point)(void));
NODISCARD pid_t task_spawn(const char* comm, void (*entry_point)(void));

DEFINE_LOCKED(task, struct task, mutex, lock)

void __task_destroy(struct task*);
DEFINE_REFCOUNTED_BASE(task, struct task, refcount, __task_destroy)

// Ensures that the current task has its own copy of the resources specified
// by `flags` (`CLONE_*`).
NODISCARD int task_unshare(unsigned long flags);

// Allocates `n` consecutive tids and returns the last one.
pid_t task_alloc_tid(size_t n);

// Finds a task by its tid. Returns NULL if not found.
struct task* task_find_by_tid(pid_t);

_Noreturn void task_exit(int status);
_Noreturn void task_exit_thread_group(int status);
_Noreturn void task_crash(int signum);

struct fs_env {
    struct path* root;
    struct path* cwd;
    _Atomic(mode_t) umask;
    struct mutex lock;
    refcount_t refcount;
};

struct fs_env* fs_env_clone(struct fs_env*);

DEFINE_LOCKED(fs_env, struct fs_env, mutex, lock)

void __fs_env_destroy(struct fs_env*);
DEFINE_REFCOUNTED_BASE(fs_env, struct fs_env, refcount, __fs_env_destroy)

NODISCARD int fs_env_chroot(struct fs_env*, struct path*);
NODISCARD int fs_env_chdir(struct fs_env*, struct path*);

struct fd_table {
    struct file* entries[OPEN_MAX];
    unsigned long closed_on_exec[DIV_CEIL(OPEN_MAX, ULONG_WIDTH)];
    struct mutex lock;
    refcount_t refcount;
};

struct fd_table* fd_table_clone(struct fd_table*);

DEFINE_LOCKED(fd_table, struct fd_table, mutex, lock)

void __fd_table_destroy(struct fd_table*);
DEFINE_REFCOUNTED_BASE(fd_table, struct fd_table, refcount, __fd_table_destroy)

// Allocates lowest-numbered file descriptor >= min_fd
// that is not already used, and sets it to the given file.
// Flags are the file descriptor flags (FD_*).
NODISCARD int fd_table_alloc_fd(struct fd_table*, int min_fd, struct file*,
                                int flags);

// Sets the file at given fd to the given file.
// If the fd is already used, replaces and frees the old file.
// Flags are the file descriptor flags (FD_*).
NODISCARD int fd_table_set_file(struct fd_table*, int fd, struct file*,
                                int flags);

int fd_table_free_fd(struct fd_table*, int fd);

struct file* fd_table_ref_file(struct fd_table*, int fd);

// Gets the file descriptor flags (FD_*) for the given fd.
NODISCARD int fd_table_get_flags(struct fd_table*, int fd);

// Sets the file descriptor flags (FD_*) for the given fd.
NODISCARD int fd_table_set_flags(struct fd_table*, int fd, int flags);

// Closes all file descriptors with FD_CLOEXEC flag set.
NODISCARD int fd_table_close_on_exec(struct fd_table*);

struct sighand {
    struct sigaction actions[NSIG - 1];
    struct spinlock lock;
    refcount_t refcount;
};

struct sighand* sighand_clone(struct sighand*);

DEFINE_LOCKED(sighand, struct sighand, spinlock, lock)

void __sighand_destroy(struct sighand*);
DEFINE_REFCOUNTED_BASE(sighand, struct sighand, refcount, __sighand_destroy)

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
DEFINE_REFCOUNTED_BASE(thread_group, struct thread_group, refcount,
                       __thread_group_destroy)

// Returns the set of pending signals for the current task,
// excluding blocked signals.
void task_get_pending_signals(struct task*, sigset_t* out_set);

void task_set_blocked_signals(const sigset_t*);

NODISCARD pid_t clone_user_task(struct registers* regs, unsigned long flags,
                                void* user_stack, pid_t* user_parent_tid,
                                pid_t* user_child_tid, void* user_tls);

#endif
