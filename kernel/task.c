#include "task.h"
#include "api/signal.h"
#include "api/sys/limits.h"
#include "cpu.h"
#include "fs/path.h"
#include "interrupts/interrupts.h"
#include "kmsg.h"
#include "memory/memory.h"
#include "panic.h"
#include "safe_string.h"
#include <common/string.h>
#include <stdatomic.h>

struct fpu_state initial_fpu_state;
static atomic_int next_tid = 1;

struct task* all_tasks;
struct spinlock all_tasks_lock;

static struct fs* fs_create(void) {
    struct fs* fs = kmalloc(sizeof(struct fs));
    if (!fs)
        return ERR_PTR(-ENOMEM);
    *fs = (struct fs){.refcount = REFCOUNT_INIT_ONE};
    fs->cwd = vfs_get_root();
    if (IS_ERR(ASSERT(fs->cwd))) {
        kfree(fs);
        return ERR_CAST(fs->cwd);
    }
    return fs;
}

struct fs* fs_clone(struct fs* fs) {
    struct fs* new_fs = kmalloc(sizeof(struct fs));
    if (!new_fs)
        return ERR_PTR(-ENOMEM);
    *new_fs = (struct fs){.refcount = REFCOUNT_INIT_ONE};
    mutex_lock(&fs->lock);
    new_fs->cwd = path_dup(fs->cwd);
    mutex_unlock(&fs->lock);
    if (IS_ERR(ASSERT(new_fs->cwd))) {
        kfree(new_fs);
        return ERR_CAST(new_fs->cwd);
    }
    return new_fs;
}

struct fs* fs_ref(struct fs* fs) {
    ASSERT(fs);
    refcount_inc(&fs->refcount);
    return fs;
}

void fs_unref(struct fs* fs) {
    if (!fs)
        return;
    if (refcount_dec(&fs->refcount))
        return;
    path_destroy_recursive(fs->cwd);
    kfree(fs);
}

static struct files* files_create(void) {
    struct files* files = kmalloc(sizeof(struct files));
    if (!files)
        return ERR_PTR(-ENOMEM);
    *files = (struct files){.refcount = REFCOUNT_INIT_ONE};
    return files;
}

struct files* files_clone(struct files* files) {
    struct files* new_files = files_create();
    if (IS_ERR(ASSERT(new_files)))
        return new_files;

    mutex_lock(&files->lock);
    memcpy(new_files->entries, files->entries, sizeof(files->entries));
    for (size_t i = 0; i < OPEN_MAX; ++i) {
        if (files->entries[i])
            file_ref(files->entries[i]);
    }
    mutex_unlock(&files->lock);

    return new_files;
}

struct files* files_ref(struct files* files) {
    ASSERT(files);
    refcount_inc(&files->refcount);
    return files;
}

void files_unref(struct files* files) {
    if (!files)
        return;
    if (refcount_dec(&files->refcount))
        return;
    for (size_t i = 0; i < OPEN_MAX; ++i) {
        if (files->entries[i]) {
            file_unref(files->entries[i]);
            files->entries[i] = NULL;
        }
    }
    kfree(files);
}

static struct sighand* sighand_create(void) {
    struct sighand* sighand = kmalloc(sizeof(struct sighand));
    if (!sighand)
        return ERR_PTR(-ENOMEM);
    *sighand = (struct sighand){.refcount = REFCOUNT_INIT_ONE};
    return sighand;
}

struct sighand* sighand_clone(struct sighand* sighand) {
    struct sighand* new_sighand = sighand_create();
    if (IS_ERR(ASSERT(new_sighand)))
        return new_sighand;
    spinlock_lock(&sighand->lock);
    memcpy(new_sighand->actions, sighand->actions, sizeof(sighand->actions));
    spinlock_unlock(&sighand->lock);
    return new_sighand;
}

struct sighand* sighand_ref(struct sighand* sighand) {
    ASSERT(sighand);
    refcount_inc(&sighand->refcount);
    return sighand;
}

void sighand_unref(struct sighand* sighand) {
    if (!sighand)
        return;
    if (refcount_dec(&sighand->refcount))
        return;
    kfree(sighand);
}

struct thread_group* thread_group_create(void) {
    struct thread_group* tg = kmalloc(sizeof(struct thread_group));
    if (!tg)
        return ERR_PTR(-ENOMEM);
    *tg = (struct thread_group){.refcount = REFCOUNT_INIT_ONE};
    return tg;
}

struct thread_group* thread_group_ref(struct thread_group* tg) {
    ASSERT(tg);
    refcount_inc(&tg->refcount);
    return tg;
}

void thread_group_unref(struct thread_group* tg) {
    if (!tg)
        return;
    if (refcount_dec(&tg->refcount))
        return;
    kfree(tg);
}

void task_init(void) {
    __asm__ volatile("fninit");
    if (cpu_has_feature(cpu_get_bsp(), X86_FEATURE_FXSR))
        __asm__ volatile("fxsave %0" : "=m"(initial_fpu_state));
    else
        __asm__ volatile("fnsave %0" : "=m"(initial_fpu_state));
}

struct task* task_get_current(void) {
    bool int_flag = push_cli();
    struct task* task = cpu_get_current()->current_task;
    pop_cli(int_flag);
    return task;
}

struct task* task_create(const char* comm, void (*entry_point)(void)) {
    struct task* task =
        kaligned_alloc(alignof(struct task), sizeof(struct task));
    if (!task)
        return ERR_PTR(-ENOMEM);
    *task = (struct task){.refcount = REFCOUNT_INIT_ONE};

    task->fpu_state = initial_fpu_state;
    task->state = TASK_RUNNING;
    strlcpy(task->comm, comm, sizeof(task->comm));

    int ret = 0;
    void* stack = NULL;

    task->fs = fs_create();
    if (IS_ERR(ASSERT(task->fs))) {
        ret = PTR_ERR(task->fs);
        task->fs = NULL;
        goto fail;
    }

    task->files = files_create();
    if (IS_ERR(ASSERT(task->files))) {
        ret = PTR_ERR(task->files);
        task->files = NULL;
        goto fail;
    }

    task->sighand = sighand_create();
    if (IS_ERR(ASSERT(task->sighand))) {
        ret = PTR_ERR(task->sighand);
        task->sighand = NULL;
        goto fail;
    }

    task->thread_group = thread_group_create();
    if (IS_ERR(ASSERT(task->thread_group))) {
        ret = PTR_ERR(task->thread_group);
        task->thread_group = NULL;
        goto fail;
    }
    task->thread_group->num_running = 1;

    task->vm = kernel_vm;

    stack = kmalloc(STACK_SIZE);
    if (!stack) {
        ret = -ENOMEM;
        goto fail;
    }

    task->kernel_stack_base = (uintptr_t)stack;
    task->kernel_stack_top = (uintptr_t)stack + STACK_SIZE;
    task->esp = task->ebp = task->kernel_stack_top;

    // Without this eager population, page fault occurs when switching to this
    // task, but page fault handler cannot run without a valid kernel stack.
    ret = vm_populate(stack, (void*)task->kernel_stack_top, true);
    if (IS_ERR(ret))
        goto fail;

    task->eip = (uintptr_t)do_iret;

    // push the argument of do_iret()
    task->esp -= sizeof(struct registers);
    *(struct registers*)task->esp = (struct registers){
        .cs = KERNEL_CS,
        .ss = KERNEL_DS,
        .gs = KERNEL_DS,
        .fs = KERNEL_DS,
        .es = KERNEL_DS,
        .ds = KERNEL_DS,
        .ebp = task->ebp,
        .esp = task->esp,
        .eip = (uintptr_t)entry_point,
        .eflags = X86_EFLAGS_IF | X86_EFLAGS_FIXED,
    };

    return task;

fail:
    kfree(stack);
    thread_group_unref(task->thread_group);
    sighand_unref(task->sighand);
    files_unref(task->files);
    fs_unref(task->fs);
    kfree(task);
    return ERR_PTR(ret);
}

struct task* task_spawn(const char* comm, void (*entry_point)(void)) {
    struct task* task = task_create(comm, entry_point);
    if (IS_ERR(ASSERT(task)))
        return task;
    task->tid = task->tgid = task->pgid = task_generate_next_tid();
    sched_register(task);
    return task;
}

struct task* task_ref(struct task* task) {
    ASSERT(task);
    refcount_inc(&task->refcount);
    return task;
}

void task_unref(struct task* task) {
    if (!task)
        return;
    if (refcount_dec(&task->refcount))
        return;

    if (task->tid == 0) {
        // struct task is usually freed in a context of its parent task,
        // but the initial task is not a child of any task. Just leak it.
        return;
    }

    ASSERT(task != current);

    thread_group_unref(task->thread_group);
    sighand_unref(task->sighand);
    files_unref(task->files);
    fs_unref(task->fs);

    if (task->vm != kernel_vm)
        vm_unref(task->vm);

    kfree((void*)task->kernel_stack_base);
    kfree(task);
}

pid_t task_generate_next_tid(void) { return atomic_fetch_add(&next_tid, 1); }

struct task* task_find_by_tid(pid_t tid) {
    spinlock_lock(&all_tasks_lock);
    struct task* it = all_tasks;
    for (; it; it = it->all_tasks_next) {
        if (it->tid == tid)
            break;
    }
    if (it)
        task_ref(it);
    spinlock_unlock(&all_tasks_lock);
    return it;
}

static noreturn void exit(int exit_status) {
    if (current->tid == 1)
        PANIC("init task exited");

    current->exit_status = exit_status;

    ASSERT(current->thread_group->num_running > 0);
    if (--current->thread_group->num_running == 0) {
        if (current->ppid && current->exit_signal)
            ASSERT_OK(task_send_signal(current->ppid, current->exit_signal, 0));
    }

    sti();
    mutex_lock(&current->lock);
    thread_group_unref(current->thread_group);
    current->thread_group = NULL;
    sighand_unref(current->sighand);
    current->sighand = NULL;
    files_unref(current->files);
    current->files = NULL;
    fs_unref(current->fs);
    current->fs = NULL;
    mutex_unlock(&current->lock);

    cli();
    spinlock_lock(&all_tasks_lock);
    for (struct task* it = all_tasks; it; it = it->all_tasks_next) {
        // Orphaned child task is adopted by init task.
        if (it->ppid == current->tgid)
            it->ppid = 1;
    }
    spinlock_unlock(&all_tasks_lock);
    current->state = TASK_DEAD;
    sched_yield(false);
    UNREACHABLE();
}

void task_exit(int status) { exit((status & 0xff) << 8); }

static noreturn void do_exit_thread_group(int exit_status) {
    int rc = task_send_signal(current->tgid, SIGKILL,
                              SIGNAL_DEST_THREAD_GROUP |
                                  SIGNAL_DEST_EXCLUDE_CURRENT);
    ASSERT(IS_OK(rc) || rc == -ESRCH);
    exit(exit_status);
}

void task_exit_thread_group(int status) {
    do_exit_thread_group((status & 0xff) << 8);
}

void task_crash(int signum) {
    ASSERT(0 < signum && signum < NSIG);
    kprintf("Task crashed: tid=%d tgid=%d signal=%d\n", current->tid,
            current->tgid, signum);
    do_exit_thread_group(signum);
}

int task_alloc_fd(int fd, struct file* file) {
    if (fd >= OPEN_MAX)
        return -EBADF;

    int ret = 0;
    mutex_lock(&current->files->lock);

    if (fd >= 0) {
        struct file** entry = current->files->entries + fd;
        file_unref(*entry);
        *entry = file_ref(file);
        ret = fd;
        goto done;
    }

    ret = -EMFILE;
    struct file** it = current->files->entries;
    for (int i = 0; i < OPEN_MAX; ++i, ++it) {
        if (*it)
            continue;
        *it = file_ref(file);
        ret = i;
        goto done;
    }

done:
    mutex_unlock(&current->files->lock);
    return ret;
}

int task_free_fd(int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    mutex_lock(&current->files->lock);
    struct file** file = current->files->entries + fd;
    if (!*file) {
        mutex_unlock(&current->files->lock);
        return -EBADF;
    }
    file_unref(*file);
    *file = NULL;
    mutex_unlock(&current->files->lock);
    return 0;
}

struct file* task_ref_file(int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return ERR_PTR(-EBADF);

    mutex_lock(&current->files->lock);
    struct file* file = current->files->entries[fd];
    if (file)
        file_ref(file);
    mutex_unlock(&current->files->lock);
    if (!file)
        return ERR_PTR(-EBADF);
    return file;
}

static enum {
    DISP_TERM,
    DISP_IGN,
    DISP_CORE,
    DISP_STOP,
    DISP_CONT,
} default_dispositions[] = {
    [SIGABRT] = DISP_CORE,   [SIGALRM] = DISP_TERM,   [SIGBUS] = DISP_CORE,
    [SIGCHLD] = DISP_IGN,    [SIGCONT] = DISP_CONT,   [SIGFPE] = DISP_CORE,
    [SIGHUP] = DISP_TERM,    [SIGILL] = DISP_CORE,    [SIGINT] = DISP_TERM,
    [SIGIO] = DISP_TERM,     [SIGKILL] = DISP_TERM,   [SIGPIPE] = DISP_TERM,
    [SIGPROF] = DISP_TERM,   [SIGPWR] = DISP_TERM,    [SIGQUIT] = DISP_CORE,
    [SIGSEGV] = DISP_CORE,   [SIGSTKFLT] = DISP_TERM, [SIGSTOP] = DISP_STOP,
    [SIGTSTP] = DISP_STOP,   [SIGSYS] = DISP_CORE,    [SIGTERM] = DISP_TERM,
    [SIGTRAP] = DISP_CORE,   [SIGTTIN] = DISP_STOP,   [SIGTTOU] = DISP_STOP,
    [SIGURG] = DISP_IGN,     [SIGUSR1] = DISP_TERM,   [SIGUSR2] = DISP_TERM,
    [SIGVTALRM] = DISP_TERM, [SIGXCPU] = DISP_CORE,   [SIGXFSZ] = DISP_CORE,
    [SIGWINCH] = DISP_IGN,
};

STATIC_ASSERT(ARRAY_SIZE(default_dispositions) == NSIG);

static void do_send_signal(struct task* task, int signum) {
    if (!task->sighand) {
        // The task is already dead.
        return;
    }

    int default_disposition = default_dispositions[signum];

    sigset_t cleared_signals = sigmask(signum);
    switch (default_disposition) {
    case DISP_CONT:
        cleared_signals |= sigmask(SIGSTOP) | sigmask(SIGTSTP) |
                           sigmask(SIGTTIN) | sigmask(SIGTTOU);
        break;
    case DISP_STOP:
        cleared_signals |= sigmask(SIGCONT);
        break;
    default:
        break;
    }
    task->pending_signals &= ~cleared_signals;

    struct sighand* sighand = task->sighand;
    spinlock_lock(&sighand->lock);
    sighandler_t handler = sighand->actions[signum - 1].sa_handler;
    spinlock_unlock(&sighand->lock);

    bool ignored = (handler == SIG_IGN) ||
                   (handler == SIG_DFL && default_disposition == DISP_IGN);
    if (!ignored)
        task->pending_signals |= sigmask(signum);
}

int task_send_signal(pid_t pid, int signum, int flags) {
    ASSERT(pid >= 0);
    unsigned num_group_flags = (bool)(flags & SIGNAL_DEST_ALL_USER_TASKS) +
                               (bool)(flags & SIGNAL_DEST_THREAD_GROUP) +
                               (bool)(flags & SIGNAL_DEST_PROCESS_GROUP);
    ASSERT(num_group_flags <= 1);
    if (signum < 0 || signum >= NSIG)
        return -EINVAL;

    bool found_dest = false;
    spinlock_lock(&all_tasks_lock);
    for (struct task* it = all_tasks; it; it = it->all_tasks_next) {
        if (flags & SIGNAL_DEST_ALL_USER_TASKS) {
            if (it->tid <= 1)
                continue;
        } else if (flags & SIGNAL_DEST_THREAD_GROUP) {
            if (it->tgid != pid)
                continue;
        } else if (flags & SIGNAL_DEST_PROCESS_GROUP) {
            if (it->pgid != pid)
                continue;
        } else if (it->tid != pid) {
            continue;
        }
        if (flags & SIGNAL_DEST_EXCLUDE_CURRENT) {
            if (it == current)
                continue;
        }
        found_dest = true;

        if (signum == 0) {
            // signum == 0 is used to check if the task exists.
            continue;
        }

        do_send_signal(it, signum);
    }
    spinlock_unlock(&all_tasks_lock);

    return found_dest ? 0 : -ESRCH;
}

int task_pop_signal(struct sigaction* out_action) {
    struct sighand* sighand = current->sighand;
    spinlock_lock(&sighand->lock);
    for (;;) {
        int signum =
            __builtin_ffs(current->pending_signals & ~current->blocked_signals);
        if (!signum)
            break;
        current->pending_signals &= ~sigmask(signum);

        struct sigaction* action = &sighand->actions[signum - 1];
        if (action->sa_handler == SIG_IGN)
            continue;

        if (action->sa_handler != SIG_DFL) {
            if (out_action)
                *out_action = *action;
            if (action->sa_flags & SA_RESETHAND)
                action->sa_handler = SIG_DFL;
            spinlock_unlock(&sighand->lock);
            return signum;
        }

        switch (default_dispositions[signum]) {
        case DISP_TERM:
        case DISP_CORE:
            spinlock_unlock(&sighand->lock);
            do_exit_thread_group(signum);
        case DISP_STOP: {
            spinlock_unlock(&sighand->lock);

            bool int_flag = push_cli();
            current->state = TASK_STOPPED;
            sched_yield(false);
            // Here we were resumed by SIGCONT.
            pop_cli(int_flag);

            spinlock_lock(&sighand->lock);
            break;
        }
        case DISP_CONT:
        case DISP_IGN:
            break;
        default:
            UNREACHABLE();
        }
    }
    spinlock_unlock(&sighand->lock);
    return 0;
}

void task_handle_signal(struct registers* regs, int signum,
                        const struct sigaction* action) {
    ASSERT(0 < signum && signum < NSIG);
    ASSERT(action->sa_flags & SA_RESTORER);

    uintptr_t esp = ROUND_DOWN(regs->esp, 16);

    // Push the context of the interrupted task
    struct sigcontext ctx = {
        .regs = *regs,
        .blocked_signals = current->blocked_signals,
    };
    esp -= sizeof(struct sigcontext);
    if (copy_to_user((void*)esp, &ctx, sizeof(struct sigcontext)))
        goto fail;

    // Push the argument of the signal handler
    esp -= sizeof(int);
    if (copy_to_user((void*)esp, &signum, sizeof(int)))
        goto fail;

    // Push the return address of the signal handler
    esp -= sizeof(uintptr_t);
    if (copy_to_user((void*)esp, &action->sa_restorer, sizeof(uintptr_t)))
        goto fail;

    regs->esp = esp;
    regs->eip = (uintptr_t)action->sa_handler;

    sigset_t new_blocked = current->blocked_signals | action->sa_mask;
    if (!(action->sa_flags & SA_NODEFER))
        new_blocked |= sigmask(signum);
    new_blocked &= ~(sigmask(SIGKILL) | sigmask(SIGSTOP));
    current->blocked_signals = new_blocked;

    return;

fail:
    task_crash(SIGSEGV);
}
