#include <common/string.h>
#include <kernel/api/linux/resource.h>
#include <kernel/api/sched.h>
#include <kernel/api/sys/prctl.h>
#include <kernel/api/sys/times.h>
#include <kernel/api/sys/wait.h>
#include <kernel/cpu.h>
#include <kernel/exec/exec.h>
#include <kernel/fs/file.h>
#include <kernel/fs/path.h>
#include <kernel/interrupts.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

long sys_exit(int status) { task_exit(status); }

long sys_exit_group(int status) { task_exit_thread_group(status); }

long sys_gettid(void) { return current->tid; }

long sys_getpid(void) { return current->thread_group->tgid; }

long sys_getppid(void) { return current->thread_group->ppid; }

long sys_getpgrp(void) { return current->thread_group->pgid; }

long sys_getpgid(pid_t pid) {
    if (pid == 0)
        return current->thread_group->pgid;
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ESRCH;
    return task->thread_group->pgid;
}

long sys_setpgid(pid_t pid, pid_t pgid) {
    if (pgid < 0)
        return -EINVAL;

    pid_t target_tgid = pid ? pid : current->thread_group->tgid;
    struct task* target FREE(task) = task_find_by_tid(target_tgid);
    if (!target)
        return -ESRCH;

    target->thread_group->pgid = pgid ? pgid : target_tgid;
    return 0;
}

long sys_getsid(pid_t pid) {
    // As we don't implement setsid(), pretend that sid is always 0.
    if (pid == 0)
        return 0;
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ESRCH;
    return 0;
}

long sys_sched_yield(void) {
    sched_yield();
    return 0;
}

long sys_execve(const char* user_pathname, char* const user_argv[],
                char* const user_envp[]) {
    if (!user_pathname)
        return -EFAULT;

    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    return execve_user(pathname, (const char* const*)user_argv,
                       (const char* const*)user_envp);
}

long sys_fork(struct registers* regs) {
    return sys_clone(regs, SIGCHLD, NULL, NULL, NULL, NULL);
}

long sys_vfork(struct registers* regs) {
    return sys_clone(regs, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL, NULL, NULL,
                     NULL);
}

static bool unblock_vfork(void* ctx) {
    struct task* task = ctx;
    return task->state == TASK_DEAD;
}

// NOLINTBEGIN(readability-non-const-parameter)
long sys_clone(struct registers* regs, unsigned long flags, void* user_stack,
               pid_t* user_parent_tid, pid_t* user_child_tid, void* user_tls) {
    // NOLINTEND(readability-non-const-parameter)
    (void)user_child_tid;

    struct task* task FREE(task) = task_clone(current, flags);
    if (IS_ERR(ASSERT(task)))
        return PTR_ERR(task);

    int rc = arch_clone_task(task, current, regs, user_stack);
    if (IS_ERR(rc))
        return rc;

    pid_t tid = task_generate_next_tid();
    task->tid = tid;
    if (!(flags & CLONE_THREAD))
        task->thread_group->tgid = tid;

    if (flags & CLONE_SETTLS) {
        rc = arch_set_tls(task, user_tls);
        if (IS_ERR(rc))
            return rc;
    }

    if (flags & CLONE_PARENT_SETTID) {
        if (copy_to_user(user_parent_tid, &tid, sizeof(pid_t)))
            return -EFAULT;
    }

    sched_register(task);

    if (flags & CLONE_VFORK) {
        rc = sched_block(unblock_vfork, task, TASK_UNINTERRUPTIBLE);
        if (IS_ERR(rc))
            return rc;
    }

    return tid;
}

struct waitpid_blocker {
    pid_t param_pid;
    pid_t current_tgid, current_pgid;
    struct task* waited_task;
};

static bool unblock_waitpid(void* data) {
    struct waitpid_blocker* blocker = data;
    SCOPED_LOCK(spinlock, &tasks_lock);

    struct task* prev = NULL;
    struct task* it = tasks;
    bool any_target_exists = false;

    while (it) {
        struct thread_group* tg = it->thread_group;
        bool is_child = tg->ppid == blocker->current_tgid;
        if (is_child) {
            bool is_target = false;
            if (blocker->param_pid < -1)
                is_target |= tg->pgid == -blocker->param_pid;
            else if (blocker->param_pid == -1)
                is_target |= tg->ppid == blocker->current_tgid;
            else if (blocker->param_pid == 0)
                is_target |= tg->pgid == blocker->current_pgid;
            else
                is_target |= tg->tgid == blocker->param_pid;
            any_target_exists |= is_target;
            if (is_target && it->state == TASK_DEAD)
                break;
        }

        prev = it;
        it = it->tasks_next;
    }
    if (!it) {
        // Unblock if no more target children exist.
        return !any_target_exists;
    }

    if (prev)
        prev->tasks_next = it->tasks_next;
    else
        tasks = it->tasks_next;
    blocker->waited_task = it;

    return true;
}

static void ticks_to_timeval(size_t ticks, struct linux_timeval* out_tv) {
    out_tv->tv_sec = ticks / CLK_TCK;
    out_tv->tv_usec = (ticks % CLK_TCK) * MICROS_PER_SEC / CLK_TCK;
}

long sys_wait4(pid_t pid, int* user_wstatus, int options,
               struct rusage* user_rusage) {
    if (options & ~WNOHANG)
        return -EINVAL;

    struct waitpid_blocker blocker = {
        .param_pid = pid,
        .current_tgid = current->thread_group->tgid,
        .current_pgid = current->thread_group->pgid,
        .waited_task = NULL,
    };
    if (options & WNOHANG) {
        if (!unblock_waitpid(&blocker))
            return 0;
    } else {
        int rc = sched_block(unblock_waitpid, &blocker, 0);
        if (rc == -EINTR)
            return -ERESTARTSYS;
        if (IS_ERR(rc))
            return rc;
    }

    struct task* waited_task = blocker.waited_task;
    if (!waited_task)
        return -ECHILD;

    pid_t result = waited_task->tid;
    int wstatus = waited_task->exit_status;

    struct rusage rusage = {0};
    ticks_to_timeval(waited_task->user_ticks, &rusage.ru_utime);
    ticks_to_timeval(waited_task->kernel_ticks, &rusage.ru_stime);

    task_unref(waited_task);

    if (user_wstatus) {
        if (copy_to_user(user_wstatus, &wstatus, sizeof(int)))
            return -EFAULT;
    }
    if (user_rusage) {
        if (copy_to_user(user_rusage, &rusage, sizeof(struct rusage)))
            return -EFAULT;
    }

    return result;
}

long sys_waitpid(pid_t pid, int* user_wstatus, int options) {
    return sys_wait4(pid, user_wstatus, options, NULL);
}

long sys_times(struct tms* user_buf) {
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

long sys_chroot(const char* user_path) {
    char path[PATH_MAX];
    ssize_t len = copy_pathname_from_user(path, user_path);
    if (IS_ERR(len))
        return len;

    struct fs* fs = current->fs;
    SCOPED_LOCK(fs, fs);

    struct path* new_root FREE(path) = vfs_resolve_path_at(fs->cwd, path, 0);
    if (IS_ERR(ASSERT(new_root)))
        return PTR_ERR(new_root);

    return fs_chroot(fs, new_root);
}

long sys_getcwd(char* user_buf, size_t size) {
    if (size <= 1)
        return -ERANGE;

    char* cwd_str FREE(kfree) = NULL;
    {
        SCOPED_LOCK(fs, current->fs);
        cwd_str = path_to_string(current->fs->cwd);
    }
    if (!cwd_str)
        return -ENOMEM;

    size_t len = strlen(cwd_str) + 1;
    if (size < len)
        return -ERANGE;
    if (copy_to_user(user_buf, cwd_str, len))
        return -EFAULT;

    return len;
}

long sys_chdir(const char* user_path) {
    char path[PATH_MAX];
    ssize_t len = copy_pathname_from_user(path, user_path);
    if (IS_ERR(len))
        return len;

    struct fs* fs = current->fs;
    SCOPED_LOCK(fs, fs);

    struct path* new_cwd FREE(path) = vfs_resolve_path_at(fs->cwd, path, 0);
    if (IS_ERR(ASSERT(new_cwd)))
        return PTR_ERR(new_cwd);

    return fs_chdir(fs, new_cwd);
}

long sys_fchdir(int fd) {
    struct file* file FREE(file) = files_ref_file(current->files, fd);
    if (IS_ERR(ASSERT(file)))
        return PTR_ERR(file);
    if (!S_ISDIR(file->inode->mode) || !file->path)
        return -ENOTDIR;

    struct fs* fs = current->fs;
    SCOPED_LOCK(fs, fs);
    return fs_chdir(fs, file->path);
}

long sys_prctl(int op, unsigned long arg2, unsigned long arg3,
               unsigned long arg4, unsigned long arg5) {
    (void)arg3;
    (void)arg4;
    (void)arg5;

    switch (op) {
    case PR_SET_NAME: {
        SCOPED_LOCK(task, current);
        char comm[sizeof(current->comm)];
        ssize_t len = strncpy_from_user(comm, (const char*)arg2, sizeof(comm));
        if (IS_ERR(len))
            return len;
        strlcpy(current->comm, comm, sizeof(current->comm));
        return 0;
    }
    case PR_GET_NAME:
        if (copy_to_user((char*)arg2, current->comm, sizeof(current->comm)))
            return -EFAULT;
        return 0;
    default:
        return -EINVAL;
    }
}
