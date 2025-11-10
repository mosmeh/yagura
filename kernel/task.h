#pragma once

#include "api/signal.h"
#include "api/sys/limits.h"
#include "fs/fs.h"
#include "gdt.h"
#include "sched.h"
#include "system.h"
#include <common/extra.h>
#include <stdnoreturn.h>

enum {
    TASK_RUNNING,
    TASK_UNINTERRUPTIBLE,
    TASK_INTERRUPTIBLE,
    TASK_DEAD,
};

struct task {
    uint32_t eip, esp, ebp, ebx, esi, edi;
    struct fpu_state fpu_state;

    pid_t tid, tgid, pgid, ppid;

    atomic_uint state;
    int exit_status;

    char comm[16];

    _Atomic(struct vm*) vm;
    uintptr_t kernel_stack_base, kernel_stack_top;
    uintptr_t arg_start, arg_end, env_start, env_end;

    struct gdt_segment tls[NUM_GDT_TLS_ENTRIES];

    struct fs* fs;
    struct files* files;

    struct sighand* sighand;
    int exit_signal;
    _Atomic(sigset_t) pending_signals;
    _Atomic(sigset_t) blocked_signals;

    unblock_fn unblock;
    void* block_data;
    bool interrupted;

    struct thread_group* thread_group;

    atomic_size_t user_ticks;
    atomic_size_t kernel_ticks;

    struct task* all_tasks_next;
    struct task* ready_queue_next;

    struct mutex lock;
    atomic_size_t ref_count;
};

struct fs {
    struct path* cwd;
    struct mutex lock;
    atomic_size_t ref_count;
};

struct fs* fs_clone(struct fs*);
void fs_ref(struct fs*);
void fs_unref(struct fs*);

struct files {
    struct file* entries[OPEN_MAX];
    struct mutex lock;
    atomic_size_t ref_count;
};

struct files* files_clone(struct files*);
void files_ref(struct files*);
void files_unref(struct files*);

struct sighand {
    struct sigaction actions[NSIG - 1];
    struct spinlock lock;
    atomic_size_t ref_count;
};

struct sighand* sighand_clone(struct sighand*);
void sighand_ref(struct sighand*);
void sighand_unref(struct sighand*);

struct sigcontext {
    sigset_t blocked_signals;
    struct registers regs;
};

struct thread_group {
    atomic_size_t num_running;
    atomic_size_t ref_count;
};

struct thread_group* thread_group_create(void);
void thread_group_ref(struct thread_group*);
void thread_group_unref(struct thread_group*);

extern struct task* all_tasks;
extern struct spinlock all_tasks_lock;
extern struct fpu_state initial_fpu_state;

void task_init(void);

#define current task_get_current()
struct task* task_get_current(void);

struct task* task_create(const char* comm, void (*entry_point)(void));
struct task* task_spawn(const char* comm, void (*entry_point)(void));

void task_ref(struct task*);
void task_unref(struct task*);

pid_t task_generate_next_tid(void);
struct task* task_find_by_tid(pid_t);

noreturn void task_exit(int status);
noreturn void task_exit_thread_group(int status);
noreturn void task_crash(int signum);

int task_user_execve(const char* pathname, const char* const* user_argv,
                     const char* const* user_envp);
int task_kernel_execve(const char* pathname, const char* const* argv,
                       const char* const* envp);

// if fd < 0, allocates lowest-numbered file descriptor that was unused
NODISCARD int task_alloc_file_descriptor(int fd, struct file*);

int task_free_file_descriptor(int fd);
struct file* task_get_file(int fd);

// Send to all tasks with tid > 1. pid_t argument is ignored.
#define SIGNAL_DEST_ALL_USER_TASKS 0x1
// Send to all tasks with given tgid
#define SIGNAL_DEST_THREAD_GROUP 0x2
// Send to all tasks with given pgid
#define SIGNAL_DEST_PROCESS_GROUP 0x4
// Don't send to the current task
#define SIGNAL_DEST_EXCLUDE_CURRENT 0x8

// Sends a signal to a task.
// Returns -ESRCH if the matching task was not found.
NODISCARD int task_send_signal(pid_t, int signum, int flags);

// Returns the signal number that should be handled by the current task,
// or 0 if no signal is pending.
// If out_action is not NULL, it is filled with the sigaction for the signal.
// This function exits the current task if it popped a fatal signal.
NODISCARD int task_pop_signal(struct sigaction* out_action);

// Handles a signal for the current task.
void task_handle_signal(struct registers* regs, int signum,
                        const struct sigaction* action);
