#include "task.h"
#include "api/signum.h"
#include "api/sys/limits.h"
#include "boot_defs.h"
#include "cpu.h"
#include "fs/path.h"
#include "interrupts/interrupts.h"
#include "kmsg.h"
#include "memory/memory.h"
#include "panic.h"
#include "scheduler.h"
#include <common/string.h>
#include <stdatomic.h>

struct fpu_state initial_fpu_state;
static atomic_int next_pid = 1;

struct task* all_tasks;
struct spinlock all_tasks_lock;

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
    *task = (struct task){.ref_count = 1};

    task->fpu_state = initial_fpu_state;
    task->state = TASK_RUNNING;
    strlcpy(task->comm, comm, sizeof(task->comm));

    int ret = 0;
    void* stack = NULL;

    task->cwd = vfs_get_root();
    if (IS_ERR(task->cwd)) {
        ret = PTR_ERR(task->cwd);
        task->cwd = NULL;
        goto fail;
    }

    ret = file_descriptor_table_init(&task->fd_table);
    if (IS_ERR(ret))
        goto fail;

    task->vm = kernel_vm;

    stack = kmalloc(STACK_SIZE);
    if (!stack) {
        ret = -ENOMEM;
        goto fail;
    }
    task->kernel_stack_base = (uintptr_t)stack;
    task->kernel_stack_top = (uintptr_t)stack + STACK_SIZE;
    task->esp = task->ebp = task->kernel_stack_top;

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
        .eflags = 0x202, // Set IF
        .user_esp = task->esp,
        .user_ss = KERNEL_DS,
    };

    return task;

fail:
    kfree(stack);
    file_descriptor_table_destroy(&task->fd_table);
    path_destroy_recursive(task->cwd);
    kfree(task);
    return ERR_PTR(ret);
}

struct task* task_spawn(const char* comm, void (*entry_point)(void)) {
    struct task* task = task_create(comm, entry_point);
    if (IS_ERR(task))
        return task;
    scheduler_register(task);
    return task;
}

void task_ref(struct task* task) {
    ASSERT(task);
    ++task->ref_count;
}

void task_unref(struct task* task) {
    if (!task)
        return;
    ASSERT(task->ref_count > 0);
    if (--task->ref_count > 0)
        return;

    if (task->pid == 0) {
        // struct task is usually freed in a context of its parent task,
        // but the initial task is not a child of any task. Just leak it.
        return;
    }

    ASSERT(task != current);

    if (task->vm != kernel_vm)
        vm_destroy(task->vm);
    file_descriptor_table_destroy(&task->fd_table);
    path_destroy_recursive(task->cwd);
    kfree((void*)task->kernel_stack_base);
    kfree(task);
}

pid_t task_generate_next_pid(void) { return atomic_fetch_add(&next_pid, 1); }

struct task* task_find_by_pid(pid_t pid) {
    spinlock_lock(&all_tasks_lock);
    struct task* it = all_tasks;
    for (; it; it = it->all_tasks_next) {
        if (it->pid == pid)
            break;
    }
    if (it)
        task_ref(it);
    spinlock_unlock(&all_tasks_lock);
    return it;
}

static noreturn void die(void) {
    if (current->pid == 1)
        PANIC("init task exited");

    sti();
    file_descriptor_table_clear(&current->fd_table);

    cli();
    spinlock_lock(&all_tasks_lock);
    for (struct task* it = all_tasks; it; it = it->all_tasks_next) {
        // Orphaned child task is adopted by init task.
        if (it->ppid == current->pid)
            it->ppid = 1;
    }
    spinlock_unlock(&all_tasks_lock);
    current->state = TASK_DEAD;
    scheduler_yield(false);
    UNREACHABLE();
}

void task_die_if_needed(void) {
    if (current->state == TASK_DYING)
        die();
}

noreturn void task_exit(int status) {
    if (status != 0)
        kprintf("\x1b[31mTask %d exited with status %d\x1b[m\n", current->pid,
                status);
    current->exit_status = (status & 0xff) << 8;
    die();
}

noreturn void task_crash_in_userland(int signum) {
    kprintf("\x1b[31mTask %d crashed with signal %d\x1b[m\n", current->pid,
            signum);
    current->exit_status = signum & 0xff;
    die();
}

static void terminate_with_signal(int signum) {
    kprintf("\x1b[31mTask %d was terminated with signal %d\x1b[m\n",
            current->pid, signum);
    current->exit_status = signum & 0xff;
    current->state = TASK_DYING;
}

void task_tick(bool in_kernel) {
    if (in_kernel)
        ++current->kernel_ticks;
    else
        ++current->user_ticks;
}

int task_alloc_file_descriptor(int fd, struct file* file) {
    if (fd >= OPEN_MAX)
        return -EBADF;

    if (fd >= 0) {
        struct file** entry = current->fd_table.entries + fd;
        if (*entry)
            return -EEXIST;
        *entry = file;
        return fd;
    }

    struct file** it = current->fd_table.entries;
    for (int i = 0; i < OPEN_MAX; ++i, ++it) {
        if (*it)
            continue;
        *it = file;
        return i;
    }
    return -EMFILE;
}

int task_free_file_descriptor(int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    struct file** file = current->fd_table.entries + fd;
    if (!*file)
        return -EBADF;
    *file = NULL;
    return 0;
}

struct file* task_get_file(int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return ERR_PTR(-EBADF);

    struct file* file = current->fd_table.entries[fd];
    if (!file)
        return ERR_PTR(-EBADF);

    return file;
}

enum {
    DISP_TERM,
    DISP_IGN,
    DISP_CORE,
    DISP_STOP,
    DISP_CONT,
};

static int get_default_disposition_for_signal(int signum) {
    switch (signum) {
    case SIGHUP:
    case SIGINT:
    case SIGKILL:
    case SIGPIPE:
    case SIGALRM:
    case SIGUSR1:
    case SIGUSR2:
    case SIGVTALRM:
    case SIGSTKFLT:
    case SIGIO:
    case SIGPROF:
    case SIGPWR:
    case SIGTERM:
        return DISP_TERM;
    case SIGCHLD:
    case SIGURG:
    case SIGWINCH:
        return DISP_IGN;
    case SIGQUIT:
    case SIGILL:
    case SIGTRAP:
    case SIGABRT:
    case SIGBUS:
    case SIGFPE:
    case SIGSEGV:
    case SIGXCPU:
    case SIGXFSZ:
    case SIGSYS:
        return DISP_CORE;
    case SIGSTOP:
    case SIGTSTP:
    case SIGTTIN:
    case SIGTTOU:
        return DISP_STOP;
    case SIGCONT:
        return DISP_CONT;
    default:
        UNREACHABLE();
    }
}

static int send_signal(struct task* task, int signum) {
    int ret = 0;
    if (signum < 0 || NSIG <= signum) {
        ret = -EINVAL;
        goto done;
    }

    int disp = get_default_disposition_for_signal(signum);
    switch (disp) {
    case DISP_TERM:
    case DISP_CORE:
        break;
    case DISP_IGN:
        goto done;
    case DISP_STOP:
    case DISP_CONT:
        UNIMPLEMENTED();
    }

    task->pending_signals |= 1 << signum;

    if (task == current)
        task_handle_pending_signals();

done:
    task_unref(task);
    return ret;
}

int task_send_signal_to_one(pid_t pid, int signum) {
    struct task* task = task_find_by_pid(pid);
    if (!task)
        return -ESRCH;
    return send_signal(task, signum);
}

int task_send_signal_to_group(pid_t pgid, int signum) {
    int ret = 0;
    spinlock_lock(&all_tasks_lock);
    for (struct task* it = all_tasks; it; it = it->all_tasks_next) {
        if (it->pgid != pgid)
            continue;
        task_ref(it);
        ret = send_signal(it, signum);
        if (IS_ERR(ret))
            break;
    }
    spinlock_unlock(&all_tasks_lock);
    return ret;
}

int task_send_signal_to_all(int signum) {
    int ret = 0;
    spinlock_lock(&all_tasks_lock);
    for (struct task* it = all_tasks; it; it = it->all_tasks_next) {
        if (it->pid <= 1)
            continue;
        task_ref(it);
        ret = send_signal(it, signum);
        if (IS_ERR(ret))
            break;
    }
    spinlock_unlock(&all_tasks_lock);
    return 0;
}

void task_handle_pending_signals(void) {
    if (!current->pending_signals)
        return;

    while (current->pending_signals) {
        int b = __builtin_ffs(current->pending_signals);
        ASSERT(b > 0);
        int signum = b - 1;
        current->pending_signals &= ~(1 << signum);
        int disp = get_default_disposition_for_signal(signum);
        switch (disp) {
        case DISP_TERM:
        case DISP_CORE:
            terminate_with_signal(signum);
            break;
        case DISP_IGN:
            continue;
        case DISP_STOP:
        case DISP_CONT:
            UNIMPLEMENTED();
        }
    }
}
