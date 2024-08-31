#include "syscall.h"
#include <common/string.h>
#include <kernel/api/sched.h>
#include <kernel/api/signum.h>
#include <kernel/api/sys/limits.h>
#include <kernel/api/sys/times.h>
#include <kernel/api/sys/wait.h>
#include <kernel/fs/path.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/scheduler.h>
#include <kernel/task.h>
#include <kernel/time.h>

void sys_exit(int status) { task_exit(status); }

void sys_exit_group(int status) {
    int rc = task_send_signal(current->tgid, SIGKILL,
                              SIGNAL_DEST_THREAD_GROUP |
                                  SIGNAL_DEST_EXCLUDE_CURRENT);
    ASSERT(IS_OK(rc) || rc == -ESRCH);
    task_exit(status);
}

pid_t sys_getpid(void) { return current->tgid; }

pid_t sys_gettid(void) { return current->tid; }

int sys_setpgid(pid_t pid, pid_t pgid) {
    if (pgid < 0)
        return -EINVAL;

    pid_t target_tgid = pid ? pid : current->tgid;
    struct task* target = task_find_by_tid(target_tgid);
    if (!target)
        return -ESRCH;

    target->pgid = pgid ? pgid : target_tgid;
    task_unref(target);
    return 0;
}

pid_t sys_getpgid(pid_t pid) {
    if (pid == 0)
        return current->pgid;
    struct task* task = task_find_by_tid(pid);
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

pid_t sys_fork(struct registers* regs) { return sys_clone(regs, 0, NULL); }

int sys_clone(struct registers* regs, unsigned long flags, void* user_stack) {
    struct task* task =
        kaligned_alloc(alignof(struct task), sizeof(struct task));
    if (!task)
        return -ENOMEM;
    *task = (struct task){
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

    pid_t tid = task_generate_next_tid();
    task->tid = tid;
    if (flags & CLONE_THREAD) {
        task->tgid = current->tgid;
        task->ppid = current->ppid;
    } else {
        task->tgid = tid;
        task->ppid = current->tgid;
    }

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
    child_regs->eax = 0; // returns 0 in the child

    if (user_stack)
        child_regs->user_esp = (uintptr_t)user_stack;

    if (flags & CLONE_VM) {
        task->vm = current->vm;
        vm_ref(task->vm);
    } else {
        task->vm = vm_clone();
        if (IS_ERR(task->vm)) {
            rc = PTR_ERR(task->vm);
            task->vm = NULL;
            goto fail;
        }
    }

    if (flags & CLONE_FS) {
        task->fs = current->fs;
        fs_ref(task->fs);
    } else {
        task->fs = fs_clone(current->fs);
        if (IS_ERR(task->fs)) {
            rc = PTR_ERR(task->fs);
            task->fs = NULL;
            goto fail;
        }
    }

    if (flags & CLONE_FILES) {
        task->files = current->files;
        files_ref(task->files);
    } else {
        task->files = files_clone(current->files);
        if (IS_ERR(task->files)) {
            rc = PTR_ERR(task->files);
            task->files = NULL;
            goto fail;
        }
    }

    scheduler_register(task);
    return tid;

fail:
    files_unref(task->files);
    fs_unref(task->fs);
    vm_unref(task->vm);
    kfree(stack);
    kfree(task);
    return rc;
}

int sys_kill(pid_t pid, int sig) {
    if (pid > 0)
        return task_send_signal(pid, sig, SIGNAL_DEST_THREAD_GROUP);
    if (pid == 0)
        return task_send_signal(current->pgid, sig, SIGNAL_DEST_PROCESS_GROUP);
    if (pid == -1)
        return task_send_signal(
            0, sig, SIGNAL_DEST_ALL_USER_TASKS | SIGNAL_DEST_EXCLUDE_CURRENT);
    return task_send_signal(-pid, sig, SIGNAL_DEST_PROCESS_GROUP);
}

struct waitpid_blocker {
    pid_t param_pid;
    pid_t current_tgid, current_pgid;
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
            if (it->ppid == blocker->current_tgid)
                is_target = true;
        } else if (blocker->param_pid == 0) {
            if (it->pgid == blocker->current_pgid)
                is_target = true;
        } else {
            if (it->tgid == blocker->param_pid)
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
        .current_tgid = current->tgid,
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

    pid_t result = waited_task->tid;
    int wstatus = waited_task->exit_status;
    task_unref(waited_task);

    if (user_wstatus) {
        if (copy_to_user(user_wstatus, &wstatus, sizeof(int)))
            return -EFAULT;
    }

    return result;
}

clock_t sys_times(struct tms* user_buf) {
    if (user_buf) {
        struct tms buf = {
            .tms_utime = current->user_ticks,
            .tms_stime = current->kernel_ticks,
        };
        if (copy_to_user(user_buf, &buf, sizeof(struct tms)))
            return -EFAULT;
    }
    return uptime;
}

int sys_getcwd(char* user_buf, size_t size) {
    if (!user_buf)
        return -EINVAL;
    if (size <= 1)
        return -ERANGE;

    mutex_lock(&current->fs->lock);
    char* cwd_str = path_to_string(current->fs->cwd);
    mutex_unlock(&current->fs->lock);
    if (!cwd_str)
        return -ENOMEM;

    size_t len = strlen(cwd_str) + 1;
    if (size < len) {
        kfree(cwd_str);
        return -ERANGE;
    }
    if (copy_to_user(user_buf, cwd_str, len)) {
        kfree(cwd_str);
        return -EFAULT;
    }

    kfree(cwd_str);
    return len;
}

int sys_chdir(const char* user_path) {
    char path[PATH_MAX];
    ssize_t path_len = strncpy_from_user(path, user_path, PATH_MAX);
    if (IS_ERR(path_len))
        return path_len;
    if (path_len >= PATH_MAX)
        return -ENAMETOOLONG;

    mutex_lock(&current->fs->lock);

    struct path* new_cwd = vfs_resolve_path_at(current->fs->cwd, path, 0);
    if (IS_ERR(new_cwd)) {
        mutex_unlock(&current->fs->lock);
        return PTR_ERR(new_cwd);
    }

    if (!S_ISDIR(new_cwd->inode->mode)) {
        path_destroy_recursive(new_cwd);
        mutex_unlock(&current->fs->lock);
        return -ENOTDIR;
    }

    path_destroy_recursive(current->fs->cwd);
    current->fs->cwd = new_cwd;

    mutex_unlock(&current->fs->lock);
    return 0;
}
