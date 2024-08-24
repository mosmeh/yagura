#include "syscall.h"
#include <common/string.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/times.h>
#include <kernel/api/sys/wait.h>
#include <kernel/boot_defs.h>
#include <kernel/fs/path.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/scheduler.h>
#include <kernel/task.h>
#include <kernel/time.h>

void sys_exit(int status) { task_exit(status); }

pid_t sys_getpid(void) { return current->pid; }

int sys_setpgid(pid_t pid, pid_t pgid) {
    if (pgid < 0)
        return -EINVAL;

    pid_t target_pid = pid ? pid : current->pid;
    struct task* target = task_find_by_pid(target_pid);
    if (!target)
        return -ESRCH;

    target->pgid = pgid ? pgid : target_pid;
    task_unref(target);
    return 0;
}

pid_t sys_getpgid(pid_t pid) {
    if (pid == 0)
        return current->pgid;
    struct task* task = task_find_by_pid(pid);
    if (!task)
        return -ESRCH;
    pid_t pgid = task->pgid;
    task_unref(task);
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

    return task_user_execve(pathname, (const char* const*)user_argv,
                            (const char* const*)user_envp);
}

pid_t sys_fork(struct registers* regs) {
    struct task* task =
        kaligned_alloc(alignof(struct task), sizeof(struct task));
    if (!task)
        return -ENOMEM;
    *task = (struct task){
        .ppid = current->pid,
        .pgid = current->pgid,
        .eip = (uintptr_t)do_iret,
        .ebx = current->ebx,
        .esi = current->esi,
        .edi = current->edi,
        .fpu_state = current->fpu_state,
        .state = TASK_RUNNING,
        .arg_start = current->arg_start,
        .arg_end = current->arg_end,
        .env_start = current->env_start,
        .env_end = current->env_end,
        .user_ticks = current->user_ticks,
        .kernel_ticks = current->kernel_ticks,
        .ref_count = 1,
    };

    pid_t pid = task_generate_next_pid();
    task->pid = pid;
    strlcpy(task->comm, current->comm, sizeof(task->comm));

    int rc = 0;
    void* stack = kmalloc(STACK_SIZE);
    if (!stack) {
        rc = -ENOMEM;
        goto fail;
    }
    task->kernel_stack_base = (uintptr_t)stack;
    task->kernel_stack_top = (uintptr_t)stack + STACK_SIZE;
    task->esp = task->ebp = task->kernel_stack_top;

    // push the argument of do_iret()
    task->esp -= sizeof(struct registers);
    struct registers* child_regs = (struct registers*)task->esp;
    *child_regs = *regs;
    child_regs->eax = 0; // fork() returns 0 in the child

    task->cwd = path_dup(current->cwd);
    if (!task->cwd) {
        rc = -ENOMEM;
        goto fail;
    }

    rc = file_descriptor_table_clone_from(&task->fd_table, &current->fd_table);
    if (IS_ERR(rc))
        goto fail;

    task->vm = vm_clone();
    if (IS_ERR(task->vm)) {
        rc = PTR_ERR(task->vm);
        task->vm = NULL;
        goto fail;
    }

    scheduler_register(task);
    return pid;

fail:
    vm_destroy(task->vm);
    file_descriptor_table_destroy(&task->fd_table);
    path_destroy_recursive(task->cwd);
    kfree(stack);
    kfree(task);
    return rc;
}

int sys_kill(pid_t pid, int sig) {
    if (pid > 0)
        return task_send_signal_to_one(pid, sig);
    if (pid == 0)
        return task_send_signal_to_group(current->pgid, sig);
    if (pid == -1)
        return task_send_signal_to_all(sig);
    return task_send_signal_to_group(-pid, sig);
}

struct waitpid_blocker {
    pid_t param_pid;
    pid_t current_pid, current_pgid;
    struct task* waited_task;
};

static bool unblock_waitpid(struct waitpid_blocker* blocker) {
    spinlock_lock(&all_tasks_lock);

    struct task* prev = NULL;
    struct task* it = all_tasks;
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
        if (is_target && it->state == TASK_DEAD)
            break;

        prev = it;
        it = it->all_tasks_next;
    }
    if (!it) {
        spinlock_unlock(&all_tasks_lock);
        if (!any_target_exists) {
            blocker->waited_task = NULL;
            return true;
        }
        return false;
    }

    if (prev)
        prev->all_tasks_next = it->all_tasks_next;
    else
        all_tasks = it->all_tasks_next;
    blocker->waited_task = it;

    spinlock_unlock(&all_tasks_lock);
    return true;
}

pid_t sys_waitpid(pid_t pid, int* user_wstatus, int options) {
    if (options & ~WNOHANG)
        return -ENOTSUP;

    struct waitpid_blocker blocker = {
        .param_pid = pid,
        .current_pid = current->pid,
        .current_pgid = current->pgid,
        .waited_task = NULL,
    };
    if (options & WNOHANG) {
        if (!unblock_waitpid(&blocker)) {
            if (blocker.waited_task) {
                task_unref(blocker.waited_task);
                return 0;
            }
            return -ECHILD;
        }
    } else {
        int rc = scheduler_block((unblock_fn)unblock_waitpid, &blocker, 0);
        if (IS_ERR(rc))
            return rc;
    }

    struct task* waited_task = blocker.waited_task;
    if (!waited_task)
        return -ECHILD;

    pid_t result = waited_task->pid;
    int wstatus = waited_task->exit_status;
    task_unref(waited_task);

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
