#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/sys/times.h>
#include <kernel/api/time.h>
#include <kernel/boot_defs.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/scheduler.h>
#include <string.h>

noreturn uintptr_t sys_exit(int status) { process_exit(status); }

uintptr_t sys_getpid(void) { return current->pid; }

uintptr_t sys_setpgid(pid_t pid, pid_t pgid) {
    if (pgid < 0)
        return -EINVAL;

    pid_t target_pid = pid ? pid : current->pid;
    struct process* target = process_find_process_by_pid(target_pid);
    if (!target)
        return -ESRCH;

    target->pgid = pgid ? pgid : target_pid;
    return 0;
}

uintptr_t sys_getpgid(pid_t pid) {
    if (pid == 0)
        return current->pgid;
    struct process* process = process_find_process_by_pid(pid);
    if (!process)
        return -ESRCH;
    return process->pgid;
}

uintptr_t sys_sched_yield(void) {
    scheduler_yield(true);
    return 0;
}

void return_to_userland(registers);

uintptr_t sys_fork(registers* regs) {
    struct process* process =
        kaligned_alloc(alignof(struct process), sizeof(struct process));
    if (!process)
        return -ENOMEM;
    *process = (struct process){0};

    process->pd = paging_clone_current_page_directory();
    if (IS_ERR(process->pd))
        return PTR_ERR(process->pd);

    process->vaddr_allocator = current->vaddr_allocator;

    process->pid = process_generate_next_pid();
    process->ppid = current->pid;
    process->pgid = current->pgid;
    process->eip = (uintptr_t)return_to_userland;
    process->ebx = current->ebx;
    process->esi = current->esi;
    process->edi = current->edi;
    process->fpu_state = current->fpu_state;
    process->state = PROCESS_STATE_RUNNING;

    process->user_ticks = current->user_ticks;
    process->kernel_ticks = current->kernel_ticks;

    process->cwd = kstrdup(current->cwd);
    if (!process->cwd)
        return -ENOMEM;

    int rc = file_descriptor_table_clone_from(&process->fd_table,
                                              &current->fd_table);
    if (IS_ERR(rc))
        return rc;

    void* stack = kmalloc(STACK_SIZE);
    if (!stack)
        return -ENOMEM;
    process->stack_top = (uintptr_t)stack + STACK_SIZE;
    process->esp = process->ebp = process->stack_top;

    // push the argument of return_to_userland()
    process->esp -= sizeof(registers);
    registers* child_regs = (registers*)process->esp;
    *child_regs = *regs;
    child_regs->eax = 0; // fork() returns 0 in the child

    scheduler_register(process);

    return process->pid;
}

uintptr_t sys_kill(pid_t pid, int sig) {
    if (pid > 0)
        return process_send_signal_to_one(pid, sig);
    if (pid == 0)
        return process_send_signal_to_group(current->pgid, sig);
    if (pid == -1)
        return process_send_signal_to_all(sig);
    return process_send_signal_to_group(-pid, sig);
}

struct waitpid_blocker {
    pid_t param_pid;
    pid_t current_pid, current_pgid;
    struct process* process;
};

static bool waitpid_shoud_unblock(struct waitpid_blocker* blocker) {
    extern struct process* all_processes;

    struct process* prev = NULL;
    struct process* it = all_processes;

    while (it) {
        if (it->state == PROCESS_STATE_DEAD) {
            if (blocker->param_pid < -1) {
                if (it->pgid == -blocker->param_pid)
                    break;
            } else if (blocker->param_pid == -1) {
                if (it->ppid == blocker->current_pid)
                    break;
            } else if (blocker->param_pid == 0) {
                if (it->pgid == blocker->current_pgid)
                    break;
            } else {
                if (it->pid == blocker->param_pid)
                    break;
            }
        }

        prev = it;
        it = it->next_in_all_processes;
    }
    if (!it)
        return false;

    if (prev)
        prev->next_in_all_processes = it->next_in_all_processes;
    else
        all_processes = it->next_in_all_processes;
    blocker->process = it;

    return true;
}

pid_t sys_waitpid(pid_t pid, int* wstatus, int options) {
    if (options != 0)
        return -ENOTSUP;

    struct waitpid_blocker blocker = {.param_pid = pid,
                                      .current_pid = current->pid,
                                      .current_pgid = current->pgid,
                                      .process = NULL};
    int rc = scheduler_block(waitpid_shoud_unblock, &blocker);
    if (IS_ERR(rc))
        return rc;

    struct process* process = blocker.process;
    ASSERT(process);
    scheduler_unregister(process);

    if (wstatus)
        *wstatus = process->exit_status;

    pid_t result = process->pid;
    kfree(process);
    return result;
}

uintptr_t sys_times(struct tms* buf) {
    buf->tms_utime = current->user_ticks;
    buf->tms_stime = current->kernel_ticks;
    return uptime;
}

static bool sleep_should_unblock(const uint32_t* deadline) {
    return uptime >= *deadline;
}

uintptr_t sys_nanosleep(const struct timespec* req, struct timespec* rem) {
    uint32_t deadline =
        uptime + req->tv_sec * CLK_TCK + req->tv_nsec * CLK_TCK / 1000000000;
    int rc = scheduler_block(sleep_should_unblock, &deadline);
    if (IS_ERR(rc))
        return rc;
    if (rem)
        rem->tv_sec = rem->tv_nsec = 0;
    return 0;
}

uintptr_t sys_getcwd(char* buf, size_t size) {
    if (!buf || size == 0)
        return -EINVAL;
    if (size < strlen(current->cwd) + 1)
        return -ERANGE;
    strlcpy(buf, current->cwd, size);
    return (uintptr_t)buf;
}

uintptr_t sys_chdir(const char* path) {
    struct file* file = vfs_resolve_path(path, current->cwd, NULL, NULL);
    if (IS_ERR(file))
        return PTR_ERR(file);
    if (!S_ISDIR(file->mode))
        return -ENOTDIR;
    current->cwd = vfs_canonicalize_path(path, current->cwd);
    return 0;
}
