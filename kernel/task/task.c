#include "private.h"
#include <arch/interrupts.h>
#include <common/integer.h>
#include <common/string.h>
#include <kernel/api/sched.h>
#include <kernel/api/sys/wait.h>
#include <kernel/kmsg.h>
#include <kernel/memory/safe_string.h>
#include <kernel/memory/vm.h>
#include <kernel/task/signal.h>
#include <kernel/task/task.h>

struct tree tasks;
struct spinlock tasks_lock;
struct waitqueue tasks_wait;

static struct task init_task = {
    .state = TASK_RUNNING,
    .comm = "init",
    .kernel_stack_base = (uintptr_t)initial_kernel_stack_base,
    .kernel_stack_top = (uintptr_t)initial_kernel_stack_top,
    .refcount = REFCOUNT_INIT_ONE,
};

static struct slab thread_group_slab;

void task_early_init(void) {
    struct cpu* cpu = cpu_get_bsp();
    init_task.cpu = cpu;
    cpu->current_task = cpu->idle_task = task_ref(&init_task);

    SLAB_INIT_FOR_TYPE(&thread_group_slab, "thread_group", struct thread_group);

    task_fs_init();
    task_signal_init();
}

void task_late_init(void) {
    ASSERT(current == &init_task);

    ASSERT(!init_task.fs_env);
    init_task.fs_env = ASSERT_PTR(fs_env_create());

    ASSERT(!init_task.fd_table);
    init_task.fd_table = ASSERT_PTR(fd_table_create());

    ASSERT(!init_task.sighand);
    init_task.sighand = ASSERT_PTR(sighand_create());

    ASSERT(!init_task.thread_group);
    init_task.thread_group = ASSERT_PTR(thread_group_create());
}

static struct task* task_clone(unsigned flags) {
    if ((flags & CLONE_SIGHAND) && !(flags & CLONE_VM))
        return ERR_PTR(-EINVAL);
    if ((flags & CLONE_THREAD) && !(flags & CLONE_SIGHAND))
        return ERR_PTR(-EINVAL);

    size_t task_struct_offset =
        ROUND_UP(KERNEL_STACK_SIZE, _Alignof(struct task));
    unsigned char* stack FREE(kfree) =
        kaligned_alloc(PAGE_SIZE, task_struct_offset + sizeof(struct task));
    if (!stack)
        return ERR_PTR(-ENOMEM);
    void* stack_top = stack + KERNEL_STACK_SIZE;

    struct task* new_task = (void*)(stack + task_struct_offset);
    *new_task = (struct task){
        .state = TASK_RUNNING,
        .kernel_stack_base = (uintptr_t)stack,
        .kernel_stack_top = (uintptr_t)stack_top,
        .arg_start = current->arg_start,
        .arg_end = current->arg_end,
        .env_start = current->env_start,
        .env_end = current->env_end,
        .blocked_signals = current->blocked_signals,
        .refcount = REFCOUNT_INIT_ONE,
    };
    strlcpy(new_task->comm, current->comm, sizeof(new_task->comm));

    struct vm* vm FREE(vm) = NULL;
    if (flags & CLONE_VM) {
        vm = vm_ref(current->vm);
    } else {
        vm = ASSERT(vm_clone(current->vm));
        if (IS_ERR(vm))
            return ERR_CAST(vm);
    }

    struct fs_env* fs_env FREE(fs_env) = NULL;
    if (flags & CLONE_FS) {
        fs_env = fs_env_ref(current->fs_env);
    } else {
        fs_env = ASSERT(fs_env_clone(current->fs_env));
        if (IS_ERR(fs_env))
            return ERR_CAST(fs_env);
    }

    struct fd_table* fd_table FREE(fd_table) = NULL;
    if (flags & CLONE_FILES) {
        fd_table = fd_table_ref(current->fd_table);
    } else {
        fd_table = ASSERT(fd_table_clone(current->fd_table));
        if (IS_ERR(fd_table))
            return ERR_CAST(fd_table);
    }

    struct sighand* sighand FREE(sighand) = NULL;
    if (flags & CLONE_SIGHAND) {
        sighand = sighand_ref(current->sighand);
    } else {
        sighand = ASSERT(sighand_clone(current->sighand));
        if (IS_ERR(sighand))
            return ERR_CAST(sighand);
    }

    struct thread_group* thread_group FREE(thread_group) = NULL;
    if (flags & CLONE_THREAD) {
        thread_group = thread_group_ref(current->thread_group);
    } else {
        thread_group = ASSERT(thread_group_create());
        if (IS_ERR(thread_group))
            return ERR_CAST(thread_group);
        thread_group->pgid = current->thread_group->pgid;
        thread_group->ppid = current->thread_group->tgid;
        thread_group->exit_signal = flags & 0xff;
    }

    TAKE_PTR(stack);
    new_task->vm = TAKE_PTR(vm);
    new_task->fs_env = TAKE_PTR(fs_env);
    new_task->fd_table = TAKE_PTR(fd_table);
    new_task->sighand = TAKE_PTR(sighand);
    new_task->thread_group = TAKE_PTR(thread_group);

    return new_task;
}

struct task* task_create(const char* comm, void (*entry_point)(void)) {
    struct task* task FREE(task) =
        ASSERT(task_clone(CLONE_VM | CLONE_FS | CLONE_FILES));
    if (IS_ERR(task))
        return task;

    strlcpy(task->comm, comm, sizeof(task->comm));

    // Kernel tasks should not have a parent.
    task->thread_group->pgid = task->thread_group->ppid = 0;

    int rc = arch_init_task(task, entry_point);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    return TAKE_PTR(task);
}

pid_t task_spawn(const char* comm, void (*entry_point)(void)) {
    struct task* task FREE(task) = ASSERT(task_create(comm, entry_point));
    if (IS_ERR(task))
        return PTR_ERR(task);
    task->tid = task->thread_group->tgid = task_alloc_tid(1);
    sched_register(task);
    return task->tid;
}

static void destroy(struct work* work) {
    struct task* task = CONTAINER_OF(work, struct task, destroy_work);
    thread_group_unref(task->thread_group);
    sighand_unref(task->sighand);
    fd_table_unref(task->fd_table);
    fs_env_unref(task->fs_env);
    vm_unref(task->vm);
    kfree((void*)task->kernel_stack_base);
}

void __task_destroy(struct task* task) {
    ASSERT(task->tid > 0); // The initial task should never exit.
    ASSERT(task != current);
    workqueue_submit_or_execute(global_workqueue, &task->destroy_work, destroy,
                                arch_interrupts_enabled());
}

int task_unshare(unsigned long flags) {
    if (flags & ~(CLONE_FS | CLONE_FILES))
        return -EINVAL;

    SCOPED_LOCK(task, current);

    struct fs_env* new_fs_env FREE(fs_env) = NULL;
    if ((flags & CLONE_FS) && refcount_get(&current->fs_env->refcount) > 1) {
        new_fs_env = ASSERT(fs_env_clone(current->fs_env));
        if (IS_ERR(new_fs_env))
            return PTR_ERR(new_fs_env);
    }

    struct fd_table* new_fd_table FREE(fd_table) = NULL;
    if ((flags & CLONE_FILES) &&
        refcount_get(&current->fd_table->refcount) > 1) {
        new_fd_table = ASSERT(fd_table_clone(current->fd_table));
        if (IS_ERR(new_fd_table))
            return PTR_ERR(new_fd_table);
    }

    if (new_fs_env) {
        struct fs_env* old_fs_env = current->fs_env;
        current->fs_env = TAKE_PTR(new_fs_env);
        fs_env_unref(old_fs_env);
    }
    if (new_fd_table) {
        struct fd_table* old_fd_table = current->fd_table;
        current->fd_table = TAKE_PTR(new_fd_table);
        fd_table_unref(old_fd_table);
    }

    return 0;
}

pid_t task_alloc_tid(size_t n) {
    static _Atomic(pid_t) last_tid = 0;
    return atomic_fetch_add(&last_tid, n) + n;
}

struct task* task_find_by_tid(pid_t tid) {
    SCOPED_LOCK(spinlock, &tasks_lock);
    struct tree_node* node = tasks.root;
    while (node) {
        struct task* task = CONTAINER_OF(node, struct task, tree_node);
        if (tid < task->tid)
            node = node->left;
        else if (tid > task->tid)
            node = node->right;
        else
            return task_ref(task);
    }
    return NULL;
}

static void notify_exit(void) {
    waitqueue_wake_all(&current->wait);

    struct thread_group* tg = current->thread_group;
    ASSERT(tg->num_running_tasks > 0);
    size_t num_running_tasks = atomic_fetch_sub(&tg->num_running_tasks, 1);
    ASSERT(num_running_tasks > 0);
    if (num_running_tasks > 1) {
        waitqueue_wake_all(&tasks_wait);
        return;
    }

    // This is the last task in this thread group.

    {
        SCOPED_LOCK(spinlock, &tasks_lock);
        for (struct tree_node* node = tree_first(&tasks); node;
             node = tree_next(node)) {
            struct task* task = CONTAINER_OF(node, struct task, tree_node);
            // Orphaned child procsses are adopted by the init process.
            if (task->thread_group->ppid == tg->tgid)
                task->thread_group->ppid = 1;
        }
    }

    if (tg->ppid && tg->exit_signal && tg->exit_signal < NSIG)
        ASSERT_OK(signal_send_to_thread_groups(0, tg->ppid, tg->exit_signal));

    waitqueue_wake_all(&tasks_wait);
}

static _Noreturn void exit(int exit_status) {
    if (current->tid == 1)
        PANIC("init task exited");

    current->exit_status = exit_status;

    arch_enable_interrupts();
    {
        SCOPED_LOCK(task, current);

        struct fd_table* fd_table = current->fd_table;
        current->fd_table = NULL;
        fd_table_unref(fd_table);

        struct fs_env* fs_env = current->fs_env;
        current->fs_env = NULL;
        fs_env_unref(fs_env);
    }

    arch_disable_interrupts();
    current->state = TASK_DEAD;
    notify_exit();
    sched_yield();
    UNREACHABLE();
}

void task_exit(int status) { exit(W_EXITCODE(status & 0xff, 0)); }

static _Noreturn void do_exit_thread_group(int exit_status) {
    // Kill all tasks in the thread group except the current task.
    int rc = signal_send_to_tasks(current->thread_group->tgid, -current->tid,
                                  SIGKILL);
    ASSERT(IS_OK(rc) || rc == -ESRCH);
    exit(exit_status);
}

void task_exit_thread_group(int status) {
    do_exit_thread_group(W_EXITCODE(status & 0xff, 0));
}

void task_terminate(int signum) {
    ASSERT(0 < signum && signum < NSIG);
    do_exit_thread_group(signum);
}

void task_crash(int signum) {
    kprintf("task: %s (tid=%d) crashed with signal %d\n", current->comm,
            current->tid, signum);
    task_terminate(signum);
}

struct thread_group* thread_group_create(void) {
    struct thread_group* tg = ASSERT(slab_alloc(&thread_group_slab));
    if (IS_ERR(tg))
        return tg;
    *tg = (struct thread_group){.refcount = REFCOUNT_INIT_ONE};
    return tg;
}

void __thread_group_destroy(struct thread_group* tg) {
    slab_free(&thread_group_slab, tg);
}

// NOLINTBEGIN(readability-non-const-parameter)
pid_t clone_user_task(struct registers* regs, unsigned long flags,
                      void* user_stack, pid_t* user_parent_tid,
                      pid_t* user_child_tid, void* user_tls) {
    // NOLINTEND(readability-non-const-parameter)
    (void)user_child_tid;

    struct task* task FREE(task) = ASSERT(task_clone(flags));
    if (IS_ERR(task))
        return PTR_ERR(task);

    int rc = arch_clone_user_task(task, current, regs, user_stack);
    if (IS_ERR(rc))
        return rc;

    pid_t tid = task_alloc_tid(1);
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

    if (flags & CLONE_VFORK)
        WAIT(&task->wait, task->state == TASK_DEAD);

    return tid;
}
