#include <common/string.h>
#include <kernel/api/sched.h>
#include <kernel/api/sys/prctl.h>
#include <kernel/api/sys/resource.h>
#include <kernel/api/sys/times.h>
#include <kernel/api/sys/wait.h>
#include <kernel/cpu.h>
#include <kernel/exec/exec.h>
#include <kernel/fs/file.h>
#include <kernel/fs/inode.h>
#include <kernel/fs/path.h>
#include <kernel/fs/vfs.h>
#include <kernel/interrupts.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

SYSCALL1(exit, int, status) { task_exit(status); }

SYSCALL1(exit_group, int, status) { task_exit_thread_group(status); }

SYSCALL0(gettid) { return current->tid; }

SYSCALL0(getpid) { return current->thread_group->tgid; }

SYSCALL0(getppid) { return current->thread_group->ppid; }

SYSCALL0(getpgrp) { return current->thread_group->pgid; }

SYSCALL1(getpgid, pid_t, pid) {
    if (pid == 0)
        return current->thread_group->pgid;
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ESRCH;
    return task->thread_group->pgid;
}

SYSCALL2(setpgid, pid_t, pid, pid_t, pgid) {
    if (pgid < 0)
        return -EINVAL;

    pid_t target_tgid = pid ? pid : current->thread_group->tgid;
    struct task* target FREE(task) = task_find_by_tid(target_tgid);
    if (!target)
        return -ESRCH;

    target->thread_group->pgid = pgid ? pgid : target_tgid;
    return 0;
}

SYSCALL1(getsid, pid_t, pid) {
    // As we don't implement setsid(), pretend that sid is always 0.
    if (pid == 0)
        return 0;
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ESRCH;
    return 0;
}

SYSCALL3(sched_getaffinity, pid_t, pid, size_t, cpusetsize, unsigned long*,
         user_mask) {
    if (cpusetsize * CHAR_BIT < num_cpus ||
        cpusetsize % sizeof(unsigned long) != 0)
        return -EINVAL;

    if (pid != 0) {
        struct task* task FREE(task) = task_find_by_tid(pid);
        if (!task)
            return -ESRCH;
    }

    // Affinity mask with all CPUs set, as we don't implement CPU affinity yet.
    unsigned long mask[DIV_CEIL(MAX_NUM_CPUS, ULONG_WIDTH)] = {0};
    size_t mask_size = DIV_CEIL(num_cpus, ULONG_WIDTH) * sizeof(unsigned long);
    for (size_t i = 0; i < num_cpus; ++i)
        mask[i / ULONG_WIDTH] |= 1UL << (i % ULONG_WIDTH);

    size_t to_copy = MIN(mask_size, cpusetsize);
    if (copy_to_user(user_mask, &mask, to_copy))
        return -EFAULT;
    return to_copy;
}

SYSCALL0(sched_yield) {
    sched_yield();
    return 0;
}

SYSCALL3(execve, const char*, user_pathname, char* const*, user_argv,
         char* const*, user_envp) {
    char pathname[PATH_MAX];
    ssize_t len = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(len))
        return len;

    return execve_user(pathname, (const char* const*)user_argv,
                       (const char* const*)user_envp);
}

SYSCALL_RAW(fork, regs) {
    return clone_user_task(regs, SIGCHLD, NULL, NULL, NULL, NULL);
}

SYSCALL_RAW(vfork, regs) {
    return clone_user_task(regs, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL, NULL,
                           NULL, NULL);
}

struct pid_waiter {
    // Parameters
    int options;
    enum pid_type {
        PIDTYPE_ANY,
        PIDTYPE_TGID,
        PIDTYPE_PGID,
    } pid_type;
    pid_t current_tgid, waited_pid;

    // Results
    struct task* task;
    int status;
};

static bool unblock_waitpid(void* data) {
    struct pid_waiter* waiter = data;
    SCOPED_LOCK(spinlock, &tasks_lock);
    for (;;) {
        struct task* prev = NULL;
        struct task* task = tasks;
        bool any_target_exists = false;

        while (task) {
            struct thread_group* tg = task->thread_group;
            bool is_target = false;
            if (tg->ppid == waiter->current_tgid) {
                switch (waiter->pid_type) {
                case PIDTYPE_ANY:
                    is_target = true;
                    break;
                case PIDTYPE_TGID:
                    is_target |= tg->tgid == waiter->waited_pid;
                    break;
                case PIDTYPE_PGID:
                    is_target |= tg->pgid == waiter->waited_pid;
                    break;
                default:
                    UNREACHABLE();
                }
            }

            if (is_target) {
                any_target_exists |= true;
                if (task->state == TASK_DEAD)
                    break;
                if ((waiter->options & WUNTRACED) &&
                    task->state == TASK_STOPPED && task->exit_status)
                    break;
            }

            prev = task;
            task = task->tasks_next;
        }
        if (!task) {
            // Unblock if no more target children exist.
            return !any_target_exists;
        }

        switch (task->state) {
        case TASK_DEAD:
            // Remove the task from the global tasks list
            if (prev)
                prev->tasks_next = task->tasks_next;
            else
                tasks = task->tasks_next;
            waiter->task = task; // The caller will free the task
            waiter->status = task->exit_status;
            return true;
        case TASK_STOPPED:
            ASSERT(waiter->options & WUNTRACED);
            int status = task->exit_status;
            if (status) {
                // The task is still alive, so don't free it yet.
                waiter->task = task_ref(task);
                waiter->status = status;
                // Do not report the same stopped child twice.
                task->exit_status = 0;
                return true;
            }
            // The task changed its exit status. Recheck the conditions.
            break;
        default:
            // The task changed its state. Recheck the conditions.
            break;
        }
    }
}

static void ticks_to_timeval(size_t ticks, struct linux_timeval* out_tv) {
    out_tv->tv_sec = ticks / CLK_TCK;
    out_tv->tv_usec = (ticks % CLK_TCK) * MICROS_PER_SEC / CLK_TCK;
}

NODISCARD static pid_t wait4(pid_t pid, int* user_wstatus, int options,
                             struct rusage* user_rusage) {
    if (options & ~(WNOHANG | WUNTRACED))
        return -EINVAL;

    if (pid == INT_MIN) // -pid overflows
        return -EINVAL;

    struct pid_waiter waiter = {
        .options = options,
        .current_tgid = current->thread_group->tgid,
        .waited_pid = -1,
    };
    if (pid < -1) {
        waiter.pid_type = PIDTYPE_PGID;
        waiter.waited_pid = -pid;
    } else if (pid == -1) {
        waiter.pid_type = PIDTYPE_ANY;
    } else if (pid == 0) {
        waiter.pid_type = PIDTYPE_PGID;
        waiter.waited_pid = current->thread_group->pgid;
    } else {
        waiter.pid_type = PIDTYPE_TGID;
        waiter.waited_pid = pid;
    }

    if (options & WNOHANG) {
        if (!unblock_waitpid(&waiter))
            return 0;
    } else {
        int rc = sched_block(unblock_waitpid, &waiter, 0);
        if (rc == -EINTR)
            return -ERESTARTSYS;
        if (IS_ERR(rc))
            return rc;
    }

    struct task* task FREE(task) = waiter.task;
    if (!task)
        return -ECHILD;

    if (user_wstatus) {
        if (copy_to_user(user_wstatus, &waiter.status, sizeof(int)))
            return -EFAULT;
    }
    if (user_rusage) {
        struct rusage rusage = {0};
        ticks_to_timeval(task->user_ticks, &rusage.ru_utime);
        ticks_to_timeval(task->kernel_ticks, &rusage.ru_stime);
        if (copy_to_user(user_rusage, &rusage, sizeof(struct rusage)))
            return -EFAULT;
    }

    return task->tid;
}

SYSCALL4(wait4, pid_t, pid, int*, user_wstatus, int, options, struct rusage*,
         user_rusage) {
    return wait4(pid, user_wstatus, options, user_rusage);
}

SYSCALL3(waitpid, pid_t, pid, int*, user_wstatus, int, options) {
    return wait4(pid, user_wstatus, options, NULL);
}

SYSCALL1(times, struct tms*, user_buf) {
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

SYSCALL1(unshare, unsigned long, flags) { return task_unshare(flags); }

SYSCALL1(umask, mode_t, mask) {
    return atomic_exchange(&current->fs_env->umask, mask & ACCESSPERMS);
}

SYSCALL1(chroot, const char*, user_path) {
    char path[PATH_MAX];
    ssize_t len = copy_pathname_from_user(path, user_path);
    if (IS_ERR(len))
        return len;

    struct fs_env* fs_env = current->fs_env;
    SCOPED_LOCK(fs_env, fs_env);

    struct path* new_root FREE(path) =
        ASSERT(vfs_resolve_path(fs_env->cwd, path, 0));
    if (IS_ERR(new_root))
        return PTR_ERR(new_root);

    return fs_env_chroot(fs_env, new_root);
}

SYSCALL2(getcwd, char*, user_buf, size_t, size) {
    if (size <= 1)
        return -ERANGE;

    char* cwd_str FREE(kfree) = NULL;
    {
        struct fs_env* fs_env = current->fs_env;
        SCOPED_LOCK(fs_env, fs_env);
        cwd_str = path_to_string(fs_env->cwd, fs_env->root);
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

SYSCALL1(chdir, const char*, user_path) {
    char path[PATH_MAX];
    ssize_t len = copy_pathname_from_user(path, user_path);
    if (IS_ERR(len))
        return len;

    struct fs_env* fs_env = current->fs_env;
    SCOPED_LOCK(fs_env, fs_env);

    struct path* new_cwd FREE(path) =
        ASSERT(vfs_resolve_path(fs_env->cwd, path, 0));
    if (IS_ERR(new_cwd))
        return PTR_ERR(new_cwd);

    return fs_env_chdir(fs_env, new_cwd);
}

SYSCALL1(fchdir, int, fd) {
    struct file* file FREE(file) =
        ASSERT(fd_table_ref_file(current->fd_table, fd));
    if (IS_ERR(file))
        return PTR_ERR(file);
    if (!S_ISDIR(file->inode->mode) || !file->path)
        return -ENOTDIR;

    struct fs_env* fs_env = current->fs_env;
    SCOPED_LOCK(fs_env, fs_env);
    return fs_env_chdir(fs_env, file->path);
}

SYSCALL5(prctl, int, op, unsigned long, arg2, unsigned long, arg3,
         unsigned long, arg4, unsigned long, arg5) {
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
