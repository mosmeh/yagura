#pragma once

#include "api/sys/limits.h"
#include "fs/fs.h"
#include "memory/memory.h"
#include "scheduler.h"
#include "system.h"
#include <common/extra.h>
#include <stdnoreturn.h>

enum {
    TASK_RUNNING,
    TASK_UNINTERRUPTIBLE,
    TASK_INTERRUPTIBLE,
    TASK_DYING,
    TASK_DEAD,
};

struct task {
    uint32_t eip, esp, ebp, ebx, esi, edi;
    struct fpu_state fpu_state;

    pid_t tid, tgid, pgid, ppid;

    atomic_uint state;
    int exit_status;

    char comm[16];

    struct vm* vm;
    uintptr_t kernel_stack_base, kernel_stack_top;
    uintptr_t arg_start, arg_end, env_start, env_end;

    struct fs* fs;
    struct files* files;

    unblock_fn unblock;
    void* block_data;
    bool block_was_interrupted;

    atomic_size_t user_ticks;
    atomic_size_t kernel_ticks;

    uint32_t pending_signals;

    struct task* all_tasks_next;
    struct task* ready_queue_next;

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

int task_user_execve(const char* pathname, const char* const* user_argv,
                     const char* const* user_envp);
int task_kernel_execve(const char* pathname, const char* const* argv,
                       const char* const* envp);

noreturn void task_exit(int status);

void task_die_if_needed(void);
void task_tick(bool in_kernel);

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

NODISCARD int task_send_signal(pid_t, int signum, int flags);

void task_handle_pending_signals(void);
