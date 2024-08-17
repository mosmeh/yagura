#pragma once

#include "fs/fs.h"
#include "memory/memory.h"
#include "scheduler.h"
#include "system.h"
#include <common/extra.h>
#include <stdnoreturn.h>

struct process {
    pid_t pid, ppid, pgid;
    uint32_t eip, esp, ebp, ebx, esi, edi;
    struct fpu_state fpu_state;

    enum {
        PROCESS_STATE_RUNNABLE,
        PROCESS_STATE_RUNNING,
        PROCESS_STATE_BLOCKED,
        PROCESS_STATE_DYING,
        PROCESS_STATE_DEAD
    } state;
    int exit_status;

    char comm[16];

    struct vm* vm;
    uintptr_t kernel_stack_base, kernel_stack_top;
    uintptr_t arg_start, arg_end, env_start, env_end;

    struct path* cwd;
    file_descriptor_table fd_table;

    unblock_fn unblock;
    void* block_data;
    int block_flags;
    bool block_was_interrupted;

    size_t user_ticks;
    size_t kernel_ticks;

    uint32_t pending_signals;

    struct process* all_processes_next;
    struct process* ready_queue_next;

    atomic_size_t ref_count;
};

extern struct process* current;
extern struct process* all_processes;
extern struct spinlock all_processes_lock;
extern struct fpu_state initial_fpu_state;

void process_init(void);

struct process* process_create(const char* comm, void (*entry_point)(void));
pid_t process_spawn(const char* comm, void (*entry_point)(void));

void process_ref(struct process*);
void process_unref(struct process*);

pid_t process_generate_next_pid(void);
struct process* process_find_by_pid(pid_t);
struct process* process_find_by_ppid(pid_t ppid);

int process_user_execve(const char* pathname, const char* const* user_argv,
                        const char* const* user_envp);
int process_kernel_execve(const char* pathname, const char* const* argv,
                          const char* const* envp);
noreturn void process_exit(int status);

noreturn void process_crash_in_userland(int signum);

void process_die_if_needed(void);
void process_tick(bool in_kernel);

// if fd < 0, allocates lowest-numbered file descriptor that was unused
NODISCARD int process_alloc_file_descriptor(int fd, struct file*);

int process_free_file_descriptor(int fd);
struct file* process_get_file(int fd);

NODISCARD int process_send_signal_to_one(pid_t pid, int signum);
NODISCARD int process_send_signal_to_group(pid_t pgid, int signum);
NODISCARD int process_send_signal_to_all(int signum);
void process_handle_pending_signals(void);
