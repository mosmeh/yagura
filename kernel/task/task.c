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

static _Atomic(pid_t) next_tid = 1;

struct task* tasks;
struct spinlock tasks_lock;

static struct task init_task = {
    .state = TASK_RUNNING,
    .comm = "init",
    .kernel_stack_base = (uintptr_t)initial_kernel_stack_base,
    .kernel_stack_top = (uintptr_t)initial_kernel_stack_top,
    .refcount = REFCOUNT_INIT_ONE,
};

static struct slab thread_group_slab;

void task_init(void) {
    struct cpu* cpu = cpu_get_bsp();
    cpu->current_task = cpu->idle_task = task_ref(&init_task);

    SLAB_INIT(&thread_group_slab, "thread_group", struct thread_group);

    task_fs_init();
    task_signal_init();
}

struct task* task_create(const char* comm, void (*entry_point)(void)) {
    struct task* task FREE(task) = ASSERT(task_clone(NULL, 0));
    if (IS_ERR(task))
        return task;

    strlcpy(task->comm, comm, sizeof(task->comm));

    int rc = arch_init_task(task, entry_point);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    return TAKE_PTR(task);
}

struct task* task_clone(const struct task* task, unsigned flags) {
    ASSERT(!task || task == current || task_is_locked_by_current(task));

    if (!task && flags)
        return ERR_PTR(-EINVAL);
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
        .refcount = REFCOUNT_INIT_ONE,
    };

    if (task) {
        strlcpy(new_task->comm, task->comm, sizeof(new_task->comm));

        new_task->arg_start = task->arg_start;
        new_task->arg_end = task->arg_end;
        new_task->env_start = task->env_start;
        new_task->env_end = task->env_end;

        new_task->blocked_signals = task->blocked_signals;

        new_task->user_ticks = task->user_ticks;
        new_task->kernel_ticks = task->kernel_ticks;
    }

    struct vm* vm FREE(vm) = NULL;
    if (!task)
        vm = vm_ref(kernel_vm);
    else if (flags & CLONE_VM)
        vm = vm_ref(task->vm);
    else
        vm = vm_clone(task->vm);
    ASSERT(vm);
    if (IS_ERR(vm))
        return ERR_CAST(vm);

    struct fs* fs FREE(fs) = NULL;
    if (!task)
        fs = fs_create();
    else if (flags & CLONE_FS)
        fs = fs_ref(task->fs);
    else
        fs = fs_clone(task->fs);
    ASSERT(fs);
    if (IS_ERR(fs))
        return ERR_CAST(fs);

    struct files* files FREE(files) = NULL;
    if (!task)
        files = files_create();
    else if (flags & CLONE_FILES)
        files = files_ref(task->files);
    else
        files = files_clone(task->files);
    ASSERT(files);
    if (IS_ERR(files))
        return ERR_CAST(files);

    struct sighand* sighand FREE(sighand) = NULL;
    if (!task)
        sighand = sighand_create();
    else if (flags & CLONE_SIGHAND)
        sighand = sighand_ref(task->sighand);
    else
        sighand = sighand_clone(task->sighand);
    ASSERT(sighand);
    if (IS_ERR(sighand))
        return ERR_CAST(sighand);

    struct thread_group* thread_group FREE(thread_group) = NULL;
    if (task && (flags & CLONE_THREAD)) {
        thread_group = thread_group_ref(task->thread_group);
    } else {
        thread_group = ASSERT(thread_group_create());
        if (IS_ERR(thread_group))
            return ERR_CAST(thread_group);
        if (task) {
            thread_group->pgid = task->thread_group->pgid;
            thread_group->ppid = task->thread_group->tgid;
        }
        thread_group->exit_signal = flags & 0xff;
    }

    TAKE_PTR(stack);
    new_task->vm = TAKE_PTR(vm);
    new_task->fs = TAKE_PTR(fs);
    new_task->files = TAKE_PTR(files);
    new_task->sighand = TAKE_PTR(sighand);
    new_task->thread_group = TAKE_PTR(thread_group);

    return new_task;
}

pid_t task_spawn(const char* comm, void (*entry_point)(void)) {
    struct task* task FREE(task) = ASSERT(task_create(comm, entry_point));
    if (IS_ERR(task))
        return PTR_ERR(task);
    task->tid = task->thread_group->tgid = task_generate_next_tid();
    sched_register(task);
    return task->tid;
}

static void destroy(struct work* work) {
    struct task* task = CONTAINER_OF(work, struct task, destroy_work);
    thread_group_unref(task->thread_group);
    sighand_unref(task->sighand);
    files_unref(task->files);
    fs_unref(task->fs);
    vm_unref(task->vm);
    kfree((void*)task->kernel_stack_base);
}

void __task_destroy(struct task* task) {
    ASSERT(task->tid > 0); // The initial task should never exit.
    ASSERT(task != current);
    workqueue_submit_or_execute(global_wq, &task->destroy_work, destroy,
                                arch_interrupts_enabled());
}

pid_t task_generate_next_tid(void) { return atomic_fetch_add(&next_tid, 1); }

struct task* task_find_by_tid(pid_t tid) {
    SCOPED_LOCK(spinlock, &tasks_lock);
    struct task* it = tasks;
    for (; it; it = it->tasks_next) {
        if (it->tid == tid)
            return task_ref(it);
    }
    return NULL;
}

static void notify_exit(struct task* task) {
    struct thread_group* tg = task->thread_group;
    ASSERT(tg->num_running_tasks > 0);
    size_t num_running_tasks = atomic_fetch_sub(&tg->num_running_tasks, 1);
    ASSERT(num_running_tasks > 0);
    if (num_running_tasks > 1)
        return;

    // This is the last task in this thread group.

    {
        SCOPED_LOCK(spinlock, &tasks_lock);
        for (struct task* it = tasks; it; it = it->tasks_next) {
            // Orphaned child procsses are adopted by the init process.
            if (it->thread_group->ppid == tg->tgid)
                it->thread_group->ppid = 1;
        }
    }

    if (tg->ppid && tg->exit_signal && tg->exit_signal < NSIG)
        ASSERT_OK(signal_send_to_thread_groups(0, tg->ppid, tg->exit_signal));
}

static _Noreturn void exit(int exit_status) {
    if (current->tid == 1)
        PANIC("init task exited");

    current->exit_status = exit_status;

    arch_enable_interrupts();
    {
        SCOPED_LOCK(task, current);

        struct files* files = current->files;
        current->files = NULL;
        files_unref(files);

        struct fs* fs = current->fs;
        current->fs = NULL;
        fs_unref(fs);
    }

    arch_disable_interrupts();
    notify_exit(current);
    current->state = TASK_DEAD;
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

static bool unblock_vfork(void* ctx) {
    struct task* task = ctx;
    return task->state == TASK_DEAD;
}

// NOLINTBEGIN(readability-non-const-parameter)
int clone_user_task(struct registers* regs, unsigned long flags,
                    void* user_stack, pid_t* user_parent_tid,
                    pid_t* user_child_tid, void* user_tls) {
    // NOLINTEND(readability-non-const-parameter)
    (void)user_child_tid;

    struct task* task FREE(task) = ASSERT(task_clone(current, flags));
    if (IS_ERR(task))
        return PTR_ERR(task);

    int rc = arch_clone_user_task(task, current, regs, user_stack);
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
