#include "private.h"
#include <common/string.h>
#include <kernel/api/asm/ldt.h>
#include <kernel/api/sched.h>
#include <kernel/api/sys/prctl.h>
#include <kernel/api/sys/times.h>
#include <kernel/api/sys/wait.h>
#include <kernel/cpu.h>
#include <kernel/exec/exec.h>
#include <kernel/fs/path.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/memory/safe_string.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

void sys_exit(int status) { task_exit(status); }

void sys_exit_group(int status) { task_exit_thread_group(status); }

pid_t sys_gettid(void) { return current->tid; }

pid_t sys_getpid(void) { return current->tgid; }

pid_t sys_getppid(void) { return current->ppid; }

pid_t sys_getpgrp(void) { return current->pgid; }

pid_t sys_getpgid(pid_t pid) {
    if (pid == 0)
        return current->pgid;
    struct task* task FREE(task) = task_find_by_tid(pid);
    if (!task)
        return -ESRCH;
    return task->pgid;
}

int sys_setpgid(pid_t pid, pid_t pgid) {
    if (pgid < 0)
        return -EINVAL;

    pid_t target_tgid = pid ? pid : current->tgid;
    struct task* target FREE(task) = task_find_by_tid(target_tgid);
    if (!target)
        return -ESRCH;

    target->pgid = pgid ? pgid : target_tgid;
    return 0;
}

int sys_sched_yield(void) {
    sched_yield();
    return 0;
}

int sys_execve(const char* user_pathname, char* const user_argv[],
               char* const user_envp[]) {
    if (!user_pathname || !user_argv || !user_envp)
        return -EFAULT;

    char pathname[PATH_MAX];
    int rc = copy_pathname_from_user(pathname, user_pathname);
    if (IS_ERR(rc))
        return rc;

    return execve_user(pathname, (const char* const*)user_argv,
                       (const char* const*)user_envp);
}

static int get_tls_entry(struct user_desc* inout_u_info) {
    struct user_desc* u = inout_u_info;
    int index = u->entry_number;
    if (index < GDT_ENTRY_TLS_MIN ||
        GDT_ENTRY_TLS_MIN + NUM_GDT_TLS_ENTRIES <= index)
        return -EINVAL;

    const struct gdt_segment* s = current->tls + (index - GDT_ENTRY_TLS_MIN);
    u->base_addr = s->base_lo | (s->base_mid << 16) | (s->base_hi << 24);
    u->limit = s->limit_lo | (s->limit_hi << 16);
    u->seg_32bit = s->db;
    u->contents = s->type >> 2;
    u->read_exec_only = !(s->type & 2);
    u->limit_in_pages = s->g;
    u->seg_not_present = !s->p;
    u->useable = s->avl;
    return 0;
}

static bool is_user_desc_empty(const struct user_desc* u) {
    if (u->base_addr || u->limit || u->seg_32bit || u->contents ||
        u->limit_in_pages || u->useable)
        return false;
    if (!u->read_exec_only && !u->seg_not_present)
        return true;
    if (u->read_exec_only && u->seg_not_present)
        return true;
    return false;
}

static bool is_user_desc_valid(const struct user_desc* u) {
    if (is_user_desc_empty(u))
        return true;
    if (!u->seg_32bit)
        return false;
    if (u->contents > 1)
        return false;
    if (u->seg_not_present)
        return false;
    return true;
}

static int set_tls_entry(struct task* task, const struct user_desc* u) {
    int index = u->entry_number;
    if (index < GDT_ENTRY_TLS_MIN ||
        GDT_ENTRY_TLS_MIN + NUM_GDT_TLS_ENTRIES <= index)
        return -EINVAL;

    struct gdt_segment* s = task->tls + (index - GDT_ENTRY_TLS_MIN);
    if (is_user_desc_empty(u)) {
        *s = (struct gdt_segment){0};
        return 0;
    }

    s->base_lo = u->base_addr & 0xffff;
    s->base_mid = (u->base_addr >> 16) & 0xff;
    s->base_hi = (u->base_addr >> 24) & 0xff;
    s->limit_lo = u->limit & 0xffff;
    s->limit_hi = (u->limit >> 16) & 0xf;

    s->type = (!u->read_exec_only << 1) | (u->contents << 2) | 1;
    s->s = 1;
    s->dpl = 3;
    s->p = !u->seg_not_present;
    s->avl = u->useable;
    s->l = 0;
    s->db = u->seg_32bit;
    s->g = u->limit_in_pages;

    return 0;
}

pid_t sys_fork(struct registers* regs) {
    return sys_clone(regs, SIGCHLD, NULL, NULL, NULL, NULL);
}

pid_t sys_vfork(struct registers* regs) {
    return sys_clone(regs, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL, NULL, NULL,
                     NULL);
}

static bool unblock_vfork(void* ctx) {
    struct task* task = ctx;
    return task->state == TASK_DEAD;
}

int sys_clone(struct registers* regs, unsigned long flags, void* user_stack,
              pid_t* user_parent_tid, pid_t* user_child_tid, void* user_tls) {
    (void)user_child_tid;

    if ((flags & CLONE_SIGHAND) && !(flags & CLONE_VM))
        return -EINVAL;
    if ((flags & CLONE_THREAD) && !(flags & CLONE_SIGHAND))
        return -EINVAL;

    struct task* task FREE(kfree) =
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
        .blocked_signals = current->blocked_signals,
        .user_ticks = current->user_ticks,
        .kernel_ticks = current->kernel_ticks,
        .refcount = REFCOUNT_INIT_ONE,
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

    void* stack FREE(kfree) = kmalloc(STACK_SIZE);
    if (!stack)
        return -ENOMEM;

    task->kernel_stack_base = (uintptr_t)stack;
    task->kernel_stack_top = (uintptr_t)stack + STACK_SIZE;
    task->esp = task->ebp = task->kernel_stack_top;

    // Without this eager population, page fault occurs when switching to this
    // task, but page fault handler cannot run without a valid kernel stack.
    int rc = vm_populate(stack, (void*)task->kernel_stack_top, true);
    if (IS_ERR(rc))
        return rc;

    // push the argument of do_iret()
    task->esp -= sizeof(struct registers);
    struct registers* child_regs = (struct registers*)task->esp;
    *child_regs = *regs;
    child_regs->eax = 0; // returns 0 in the child

    if (user_stack)
        child_regs->esp = (uintptr_t)user_stack;

    struct vm* vm FREE(vm) = NULL;
    if (flags & CLONE_VM) {
        vm = vm_ref(current->vm);
    } else {
        vm = vm_clone(current->vm);
        if (IS_ERR(ASSERT(vm)))
            return PTR_ERR(vm);
    }

    struct fs* fs FREE(fs) = NULL;
    if (flags & CLONE_FS) {
        fs = fs_ref(current->fs);
    } else {
        fs = fs_clone(current->fs);
        if (IS_ERR(ASSERT(fs)))
            return PTR_ERR(fs);
    }

    struct files* files FREE(files) = NULL;
    if (flags & CLONE_FILES) {
        files = files_ref(current->files);
    } else {
        files = files_clone(current->files);
        if (IS_ERR(ASSERT(files)))
            return PTR_ERR(files);
    }

    struct sighand* sighand FREE(sighand) = NULL;
    if (flags & CLONE_SIGHAND) {
        sighand = sighand_ref(current->sighand);
    } else {
        sighand = sighand_clone(current->sighand);
        if (IS_ERR(ASSERT(sighand)))
            return PTR_ERR(sighand);
    }

    struct thread_group* thread_group FREE(thread_group) = NULL;
    if (flags & CLONE_THREAD) {
        thread_group = thread_group_ref(current->thread_group);
    } else {
        thread_group = thread_group_create();
        if (IS_ERR(ASSERT(thread_group)))
            return PTR_ERR(thread_group);
        task->exit_signal = flags & 0xff;
    }

    memcpy(task->tls, current->tls, sizeof(current->tls));

    if (flags & CLONE_SETTLS) {
        struct user_desc u_info;
        if (copy_from_user(&u_info, user_tls, sizeof(struct user_desc)))
            return -EFAULT;
        if (!is_user_desc_valid(&u_info))
            return -EINVAL;
        rc = set_tls_entry(task, &u_info);
        if (IS_ERR(rc))
            return rc;
    }

    if (flags & CLONE_PARENT_SETTID) {
        if (copy_to_user(user_parent_tid, &tid, sizeof(pid_t)))
            return -EFAULT;
    }

    ++thread_group->num_running;

    // Commit resources
    TAKE_PTR(stack);
    task->vm = TAKE_PTR(vm);
    task->fs = TAKE_PTR(fs);
    task->files = TAKE_PTR(files);
    task->sighand = TAKE_PTR(sighand);
    task->thread_group = TAKE_PTR(thread_group);

    sched_register(task);

    if (flags & CLONE_VFORK)
        rc = sched_block(unblock_vfork, task, TASK_UNINTERRUPTIBLE);

    task_unref(task);
    TAKE_PTR(task); // Avoid double free

    if (IS_ERR(rc))
        return rc;
    return tid;
}

int sys_get_thread_area(struct user_desc* user_u_info) {
    struct user_desc u_info;
    if (copy_from_user(&u_info, user_u_info, sizeof(struct user_desc)))
        return -EFAULT;
    int rc = get_tls_entry(&u_info);
    if (IS_ERR(rc))
        return rc;
    if (copy_to_user(user_u_info, &u_info, sizeof(struct user_desc)))
        return -EFAULT;
    return 0;
}

static int find_free_tls_entry(void) {
    for (size_t i = 0; i < ARRAY_SIZE(current->tls); ++i) {
        const struct gdt_segment* s = current->tls + i;
        if (s->base_lo || s->base_mid || s->base_hi || s->limit_lo ||
            s->limit_hi || s->access || s->flags)
            continue;
        return i + GDT_ENTRY_TLS_MIN;
    }
    return -ESRCH;
}

int sys_set_thread_area(struct user_desc* user_u_info) {
    struct user_desc u_info;
    if (copy_from_user(&u_info, user_u_info, sizeof(struct user_desc)))
        return -EFAULT;

    if (!is_user_desc_valid(&u_info))
        return -EINVAL;

    int index = u_info.entry_number;
    bool should_alloc = index == -1;
    if (should_alloc) {
        index = find_free_tls_entry();
        if (IS_ERR(index))
            return index;
    }
    u_info.entry_number = index;

    {
        SCOPED_DISABLE_INTERRUPTS();

        int rc = set_tls_entry(current, &u_info);
        if (IS_ERR(rc))
            return rc;

        memcpy(cpu_get_current()->gdt + GDT_ENTRY_TLS_MIN, current->tls,
               sizeof(current->tls));
    }

    if (should_alloc) {
        if (copy_to_user((unsigned char*)user_u_info +
                             offsetof(struct user_desc, entry_number),
                         &u_info.entry_number, sizeof(u_info.entry_number)))
            return -EFAULT;
    }

    return 0;
}

struct waitpid_blocker {
    pid_t param_pid;
    pid_t current_tgid, current_pgid;
    struct task* waited_task;
};

static bool unblock_waitpid(void* data) {
    struct waitpid_blocker* blocker = data;
    SCOPED_LOCK(spinlock, &all_tasks_lock);

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

    return true;
}

pid_t sys_wait4(pid_t pid, int* user_wstatus, int options,
                struct rusage* user_rusage) {
    if ((options & ~WNOHANG) || user_rusage)
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
    task_unref(waited_task);

    if (user_wstatus) {
        if (copy_to_user(user_wstatus, &wstatus, sizeof(int)))
            return -EFAULT;
    }

    return result;
}

pid_t sys_waitpid(pid_t pid, int* user_wstatus, int options) {
    return sys_wait4(pid, user_wstatus, options, NULL);
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

int sys_chroot(const char* user_path) {
    char path[PATH_MAX];
    int rc = copy_pathname_from_user(path, user_path);
    if (IS_ERR(rc))
        return rc;

    struct fs* fs = current->fs;
    SCOPED_LOCK(fs, fs);

    struct path* new_root FREE(path) = vfs_resolve_path_at(fs->cwd, path, 0);
    if (IS_ERR(ASSERT(new_root)))
        return PTR_ERR(new_root);

    return fs_chroot(fs, new_root);
}

int sys_getcwd(char* user_buf, size_t size) {
    if (!user_buf)
        return -EINVAL;
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

int sys_chdir(const char* user_path) {
    char path[PATH_MAX];
    int rc = copy_pathname_from_user(path, user_path);
    if (IS_ERR(rc))
        return rc;

    struct fs* fs = current->fs;
    SCOPED_LOCK(fs, fs);

    struct path* new_cwd FREE(path) = vfs_resolve_path_at(fs->cwd, path, 0);
    if (IS_ERR(ASSERT(new_cwd)))
        return PTR_ERR(new_cwd);

    return fs_chdir(fs, new_cwd);
}

int sys_prctl(int op, unsigned long arg2, unsigned long arg3,
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
