#include "syscall.h"
#include <common/string.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/times.h>
#include <kernel/api/sys/wait.h>
#include <kernel/boot_defs.h>
#include <kernel/fs/path.h>
#include <kernel/interrupts.h>
#include <kernel/panic.h>
#include <kernel/process.h>
#include <kernel/safe_string.h>
#include <kernel/scheduler.h>
#include <kernel/time.h>

void sys_exit(int status) { process_exit(status); }

pid_t sys_getpid(void) { return current->pid; }

int sys_setpgid(pid_t pid, pid_t pgid) {
    if (pgid < 0)
        return -EINVAL;

    pid_t target_pid = pid ? pid : current->pid;
    struct process* target = process_find_by_pid(target_pid);
    if (!target)
        return -ESRCH;

    target->pgid = pgid ? pgid : target_pid;
    process_unref(target);
    return 0;
}

pid_t sys_getpgid(pid_t pid) {
    if (pid == 0)
        return current->pgid;
    struct process* process = process_find_by_pid(pid);
    if (!process)
        return -ESRCH;
    pid_t pgid = process->pgid;
    process_unref(process);
    return pgid;
}

int sys_sched_yield(void) {
    scheduler_yield(true);
    return 0;
}

int sys_execve(const char* user_pathname, char* const user_argv[],
               char* const user_envp[]) {
    if (!user_pathname || !user_argv || !user_envp)
        return -EFAULT;

    char pathname[PATH_MAX];
    ssize_t pathname_len = strncpy_from_user(pathname, user_pathname, PATH_MAX);
    if (IS_ERR(pathname_len))
        return pathname_len;
    if (pathname_len >= PATH_MAX)
        return -ENAMETOOLONG;

    return process_user_execve(pathname, (const char* const*)user_argv,
                               (const char* const*)user_envp);
}

void return_to_userland(struct registers);

pid_t sys_fork(struct registers* regs) {
    struct process* process =
        kaligned_alloc(alignof(struct process), sizeof(struct process));
    if (!process)
        return -ENOMEM;
    *process = (struct process){
        .ppid = current->pid,
        .pgid = current->pgid,
        .eip = (uintptr_t)return_to_userland,
        .ebx = current->ebx,
        .esi = current->esi,
        .edi = current->edi,
        .fpu_state = current->fpu_state,
        .state = PROCESS_STATE_RUNNABLE,
        .arg_start = current->arg_start,
        .arg_end = current->arg_end,
        .env_start = current->env_start,
        .env_end = current->env_end,
        .user_ticks = current->user_ticks,
        .kernel_ticks = current->kernel_ticks,
        .ref_count = 1,
    };

    pid_t pid = process_generate_next_pid();
    process->pid = pid;
    strlcpy(process->comm, current->comm, sizeof(process->comm));

    int rc = 0;
    void* stack = kmalloc(STACK_SIZE);
    if (!stack) {
        rc = -ENOMEM;
        goto fail;
    }
    process->kernel_stack_base = (uintptr_t)stack;
    process->kernel_stack_top = (uintptr_t)stack + STACK_SIZE;
    process->esp = process->ebp = process->kernel_stack_top;

    // push the argument of return_to_userland()
    process->esp -= sizeof(struct registers);
    struct registers* child_regs = (struct registers*)process->esp;
    *child_regs = *regs;
    child_regs->eax = 0; // fork() returns 0 in the child

    process->cwd = path_dup(current->cwd);
    if (!process->cwd) {
        rc = -ENOMEM;
        goto fail;
    }

    rc = file_descriptor_table_clone_from(&process->fd_table,
                                          &current->fd_table);
    if (IS_ERR(rc))
        goto fail;

    process->vm = vm_clone();
    if (IS_ERR(process->vm)) {
        rc = PTR_ERR(process->vm);
        process->vm = NULL;
        goto fail;
    }

    scheduler_register(process);
    return pid;

fail:
    vm_destroy(process->vm);
    file_descriptor_table_destroy(&process->fd_table);
    path_destroy_recursive(process->cwd);
    kfree(stack);
    kfree(process);
    return rc;
}

int sys_kill(pid_t pid, int sig) {
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
    struct process* waited_process;
};

static bool unblock_waitpid(struct waitpid_blocker* blocker) {
    bool int_flag = push_cli();

    struct process* prev = NULL;
    struct process* it = all_processes;
    bool any_target_exists = false;

    while (it) {
        bool is_target = false;
        if (blocker->param_pid < -1) {
            if (it->pgid == -blocker->param_pid)
                is_target = true;
        } else if (blocker->param_pid == -1) {
            if (it->ppid == blocker->current_pid)
                is_target = true;
        } else if (blocker->param_pid == 0) {
            if (it->pgid == blocker->current_pgid)
                is_target = true;
        } else {
            if (it->pid == blocker->param_pid)
                is_target = true;
        }
        any_target_exists |= is_target;
        if (is_target && it->state == PROCESS_STATE_DEAD)
            break;

        prev = it;
        it = it->next_in_all_processes;
    }
    if (!it) {
        pop_cli(int_flag);
        if (!any_target_exists) {
            blocker->waited_process = NULL;
            return true;
        }
        return false;
    }

    if (prev)
        prev->next_in_all_processes = it->next_in_all_processes;
    else
        all_processes = it->next_in_all_processes;
    blocker->waited_process = it;

    pop_cli(int_flag);
    return true;
}

pid_t sys_waitpid(pid_t pid, int* user_wstatus, int options) {
    if (options & ~WNOHANG)
        return -ENOTSUP;

    struct waitpid_blocker blocker = {
        .param_pid = pid,
        .current_pid = current->pid,
        .current_pgid = current->pgid,
        .waited_process = NULL,
    };
    if (options & WNOHANG) {
        if (!unblock_waitpid(&blocker)) {
            if (blocker.waited_process) {
                process_unref(blocker.waited_process);
                return 0;
            }
            return -ECHILD;
        }
    } else {
        int rc = scheduler_block((unblock_fn)unblock_waitpid, &blocker, 0);
        if (IS_ERR(rc))
            return rc;
    }

    struct process* waited_process = blocker.waited_process;
    if (!waited_process)
        return -ECHILD;

    pid_t result = waited_process->pid;
    int wstatus = waited_process->exit_status;
    process_unref(waited_process);

    if (user_wstatus) {
        if (copy_to_user(user_wstatus, &wstatus, sizeof(int)))
            return -EFAULT;
    }

    return result;
}

clock_t sys_times(struct tms* user_buf) {
    struct tms buf = {.tms_utime = current->user_ticks,
                      .tms_stime = current->kernel_ticks};
    if (copy_to_user(user_buf, &buf, sizeof(struct tms)))
        return -EFAULT;
    return uptime;
}

char* sys_getcwd(char* user_buf, size_t size) {
    if (!user_buf || size == 0)
        return ERR_PTR(-EINVAL);

    char* cwd_str = path_to_string(current->cwd);
    if (!cwd_str)
        return ERR_PTR(-ENOMEM);

    size_t len = strlen(cwd_str) + 1;
    if (size < len) {
        kfree(cwd_str);
        return ERR_PTR(-ERANGE);
    }
    if (copy_to_user(user_buf, cwd_str, len)) {
        kfree(cwd_str);
        return ERR_PTR(-EFAULT);
    }

    kfree(cwd_str);
    return user_buf;
}

int sys_chdir(const char* user_path) {
    char path[PATH_MAX];
    ssize_t path_len = strncpy_from_user(path, user_path, PATH_MAX);
    if (IS_ERR(path_len))
        return path_len;
    if (path_len >= PATH_MAX)
        return -ENAMETOOLONG;

    struct path* new_cwd = vfs_resolve_path_at(current->cwd, path, 0);
    if (IS_ERR(new_cwd))
        return PTR_ERR(new_cwd);

    if (!S_ISDIR(new_cwd->inode->mode)) {
        path_destroy_recursive(new_cwd);
        return -ENOTDIR;
    }

    path_destroy_recursive(current->cwd);
    current->cwd = new_cwd;

    return 0;
}
