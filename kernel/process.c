#include "process.h"
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

struct process* all_processes;
struct spinlock all_processes_lock;

void process_init(void) {
    __asm__ volatile("fninit");
    if (cpu_has_feature(cpu_get_bsp(), X86_FEATURE_FXSR))
        __asm__ volatile("fxsave %0" : "=m"(initial_fpu_state));
    else
        __asm__ volatile("fnsave %0" : "=m"(initial_fpu_state));
}

struct process* process_get_current(void) {
    bool int_flag = push_cli();
    struct process* process = cpu_get_current()->current_process;
    pop_cli(int_flag);
    return process;
}

struct process* process_create(const char* comm, void (*entry_point)(void)) {
    struct process* process =
        kaligned_alloc(alignof(struct process), sizeof(struct process));
    if (!process)
        return ERR_PTR(-ENOMEM);
    *process = (struct process){.ref_count = 1};

    process->fpu_state = initial_fpu_state;
    process->state = PROCESS_STATE_RUNNING;
    strlcpy(process->comm, comm, sizeof(process->comm));

    int ret = 0;
    void* stack = NULL;

    process->cwd = vfs_get_root();
    if (IS_ERR(process->cwd)) {
        ret = PTR_ERR(process->cwd);
        process->cwd = NULL;
        goto fail;
    }

    ret = file_descriptor_table_init(&process->fd_table);
    if (IS_ERR(ret))
        goto fail;

    process->vm = kernel_vm;

    stack = kmalloc(STACK_SIZE);
    if (!stack) {
        ret = -ENOMEM;
        goto fail;
    }
    process->kernel_stack_base = (uintptr_t)stack;
    process->kernel_stack_top = (uintptr_t)stack + STACK_SIZE;
    process->esp = process->ebp = process->kernel_stack_top;

    process->eip = (uintptr_t)do_iret;

    // push the argument of do_iret()
    process->esp -= sizeof(struct registers);
    *(struct registers*)process->esp = (struct registers){
        .cs = KERNEL_CS,
        .ss = KERNEL_DS,
        .gs = KERNEL_DS,
        .fs = KERNEL_DS,
        .es = KERNEL_DS,
        .ds = KERNEL_DS,
        .ebp = process->ebp,
        .esp = process->esp,
        .eip = (uintptr_t)entry_point,
        .eflags = 0x202, // Set IF
        .user_esp = process->esp,
        .user_ss = KERNEL_DS,
    };

    return process;

fail:
    kfree(stack);
    file_descriptor_table_destroy(&process->fd_table);
    path_destroy_recursive(process->cwd);
    kfree(process);
    return ERR_PTR(ret);
}

struct process* process_spawn(const char* comm, void (*entry_point)(void)) {
    struct process* process = process_create(comm, entry_point);
    if (IS_ERR(process))
        return process;
    scheduler_register(process);
    return process;
}

void process_ref(struct process* process) {
    ASSERT(process);
    ++process->ref_count;
}

void process_unref(struct process* process) {
    if (!process)
        return;
    ASSERT(process->ref_count > 0);
    if (--process->ref_count > 0)
        return;

    if (process->pid == 0) {
        // struct process is usually freed in a context of its parent process,
        // but the initial process is not a child of any process. Just leak it.
        return;
    }

    ASSERT(process != current);

    if (process->vm != kernel_vm)
        vm_destroy(process->vm);
    file_descriptor_table_destroy(&process->fd_table);
    path_destroy_recursive(process->cwd);
    kfree((void*)process->kernel_stack_base);
    kfree(process);
}

pid_t process_generate_next_pid(void) { return atomic_fetch_add(&next_pid, 1); }

struct process* process_find_by_pid(pid_t pid) {
    spinlock_lock(&all_processes_lock);
    struct process* it = all_processes;
    for (; it; it = it->all_processes_next) {
        if (it->pid == pid)
            break;
    }
    if (it)
        process_ref(it);
    spinlock_unlock(&all_processes_lock);
    return it;
}

struct process* process_find_by_ppid(pid_t ppid) {
    spinlock_lock(&all_processes_lock);
    struct process* it = all_processes;
    for (; it; it = it->all_processes_next) {
        if (it->ppid == ppid)
            break;
    }
    if (it)
        process_ref(it);
    spinlock_unlock(&all_processes_lock);
    return it;
}

static noreturn void die(void) {
    if (current->pid == 1)
        PANIC("init process exited");

    sti();
    file_descriptor_table_clear(&current->fd_table);

    cli();
    spinlock_lock(&all_processes_lock);
    for (struct process* it = all_processes; it; it = it->all_processes_next) {
        // Orphaned child process is adopted by init process.
        if (it->ppid == current->pid)
            it->ppid = 1;
    }
    spinlock_unlock(&all_processes_lock);
    current->state = PROCESS_STATE_DEAD;
    scheduler_yield(false);
    UNREACHABLE();
}

void process_die_if_needed(void) {
    if (current->state == PROCESS_STATE_DYING)
        die();
}

noreturn void process_exit(int status) {
    if (status != 0)
        kprintf("\x1b[31mProcess %d exited with status %d\x1b[m\n",
                current->pid, status);
    current->exit_status = (status & 0xff) << 8;
    die();
}

noreturn void process_crash_in_userland(int signum) {
    kprintf("\x1b[31mProcess %d crashed with signal %d\x1b[m\n", current->pid,
            signum);
    current->exit_status = signum & 0xff;
    die();
}

static void terminate_with_signal(int signum) {
    kprintf("\x1b[31mProcess %d was terminated with signal %d\x1b[m\n",
            current->pid, signum);
    current->exit_status = signum & 0xff;
    current->state = PROCESS_STATE_DYING;
}

void process_tick(bool in_kernel) {
    if (in_kernel)
        ++current->kernel_ticks;
    else
        ++current->user_ticks;
}

int process_alloc_file_descriptor(int fd, struct file* file) {
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

int process_free_file_descriptor(int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    struct file** file = current->fd_table.entries + fd;
    if (!*file)
        return -EBADF;
    *file = NULL;
    return 0;
}

struct file* process_get_file(int fd) {
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

static int send_signal(struct process* process, int signum) {
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

    process->pending_signals |= 1 << signum;

    if (process == current)
        process_handle_pending_signals();

done:
    process_unref(process);
    return ret;
}

int process_send_signal_to_one(pid_t pid, int signum) {
    struct process* process = process_find_by_pid(pid);
    if (!process)
        return -ESRCH;
    return send_signal(process, signum);
}

int process_send_signal_to_group(pid_t pgid, int signum) {
    int ret = 0;
    spinlock_lock(&all_processes_lock);
    for (struct process* it = all_processes; it; it = it->all_processes_next) {
        if (it->pgid != pgid)
            continue;
        process_ref(it);
        ret = send_signal(it, signum);
        if (IS_ERR(ret))
            break;
    }
    spinlock_unlock(&all_processes_lock);
    return ret;
}

int process_send_signal_to_all(int signum) {
    int ret = 0;
    spinlock_lock(&all_processes_lock);
    for (struct process* it = all_processes; it; it = it->all_processes_next) {
        if (it->pid <= 1)
            continue;
        process_ref(it);
        ret = send_signal(it, signum);
        if (IS_ERR(ret))
            break;
    }
    spinlock_unlock(&all_processes_lock);
    return 0;
}

void process_handle_pending_signals(void) {
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
