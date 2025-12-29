#include "private.h"
#include <common/string.h>
#include <kernel/cpu.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/task/task.h>

struct fpu_state initial_fpu_state;
static atomic_int next_tid = 1;

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

    __asm__ volatile("fninit");
    if (cpu_has_feature(cpu, X86_FEATURE_FXSR))
        __asm__ volatile("fxsave %0" : "=m"(initial_fpu_state));
    else
        __asm__ volatile("fnsave %0" : "=m"(initial_fpu_state));

    cpu->current_task = cpu->idle_task = task_ref(&init_task);

    slab_init(&thread_group_slab, "thread_group", sizeof(struct thread_group));

    task_fs_init();
    task_signal_init();
}

struct task* task_get_current(void) {
    SCOPED_DISABLE_INTERRUPTS();
    struct task* task = cpu_get_current()->current_task;
    ASSERT(task);
    return task;
}

struct task* task_create(const char* comm, void (*entry_point)(void)) {
    struct task* task FREE(kfree) =
        kaligned_alloc(alignof(struct task), sizeof(struct task));
    if (!task)
        return ERR_PTR(-ENOMEM);
    *task = (struct task){.refcount = REFCOUNT_INIT_ONE};

    task->fpu_state = initial_fpu_state;
    task->state = TASK_RUNNING;
    strlcpy(task->comm, comm, sizeof(task->comm));

    struct fs* fs FREE(fs) = fs_create();
    if (IS_ERR(ASSERT(fs)))
        return ERR_CAST(fs);

    struct files* files FREE(files) = files_create();
    if (IS_ERR(ASSERT(files)))
        return ERR_CAST(files);

    struct sighand* sighand FREE(sighand) = sighand_create();
    if (IS_ERR(ASSERT(sighand)))
        return ERR_CAST(sighand);

    struct thread_group* thread_group FREE(thread_group) =
        thread_group_create();
    if (IS_ERR(ASSERT(thread_group)))
        return ERR_CAST(thread_group);
    thread_group->num_running_tasks = 1;

    void* stack FREE(kfree) = kmalloc(STACK_SIZE);
    if (!stack)
        return ERR_PTR(-ENOMEM);

    task->vm = kernel_vm;
    task->kernel_stack_base = (uintptr_t)stack;
    task->kernel_stack_top = (uintptr_t)stack + STACK_SIZE;
    task->esp = task->ebp = task->kernel_stack_top;

    // Without this eager population, page fault occurs when switching to this
    // task, but page fault handler cannot run without a valid kernel stack.
    int ret = vm_populate(stack, (void*)task->kernel_stack_top, true);
    if (IS_ERR(ret))
        return ERR_PTR(ret);

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

    // Commit resources
    task->fs = TAKE_PTR(fs);
    task->files = TAKE_PTR(files);
    task->sighand = TAKE_PTR(sighand);
    task->thread_group = TAKE_PTR(thread_group);
    TAKE_PTR(stack);

    return TAKE_PTR(task);
}

pid_t task_spawn(const char* comm, void (*entry_point)(void)) {
    struct task* task FREE(task) = task_create(comm, entry_point);
    if (IS_ERR(ASSERT(task)))
        return PTR_ERR(task);
    task->tid = task->thread_group->tgid = task_generate_next_tid();
    sched_register(task);
    return task->tid;
}

void __task_destroy(struct task* task) {
    ASSERT(task->tid > 0); // The initial task should never exit.
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

    if (tg->ppid && tg->exit_signal)
        ASSERT_OK(signal_send_to_thread_groups(0, tg->ppid, tg->exit_signal));
}

static noreturn void exit(int exit_status) {
    if (current->tid == 1)
        PANIC("init task exited");

    current->exit_status = exit_status;

    enable_interrupts();
    {
        SCOPED_LOCK(task, current);

        struct files* files = current->files;
        current->files = NULL;
        files_unref(files);

        struct fs* fs = current->fs;
        current->fs = NULL;
        fs_unref(fs);
    }

    disable_interrupts();
    notify_exit(current);
    current->state = TASK_DEAD;
    sched_yield();
    UNREACHABLE();
}

void task_exit(int status) { exit((status & 0xff) << 8); }

static noreturn void do_exit_thread_group(int exit_status) {
    // Kill all tasks in the thread group except the current task.
    int rc = signal_send_to_tasks(current->thread_group->tgid, -current->tid,
                                  SIGKILL);
    ASSERT(IS_OK(rc) || rc == -ESRCH);
    exit(exit_status);
}

void task_exit_thread_group(int status) {
    do_exit_thread_group((status & 0xff) << 8);
}

void task_terminate(int signum) {
    ASSERT(0 < signum && signum < NSIG);
    do_exit_thread_group(signum);
}

void task_crash(int signum) {
    kprintf("Task crashed: tid=%d signal=%d\n", current->tid, signum);
    task_terminate(signum);
}

struct thread_group* thread_group_create(void) {
    struct thread_group* tg = slab_alloc(&thread_group_slab);
    if (IS_ERR(tg))
        return tg;
    *tg = (struct thread_group){.refcount = REFCOUNT_INIT_ONE};
    return tg;
}

void __thread_group_destroy(struct thread_group* tg) {
    slab_free(&thread_group_slab, tg);
}
