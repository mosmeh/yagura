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
static atomic_int next_tid = 1;

struct task* all_tasks;
struct spinlock all_tasks_lock;

static struct fs* fs_create(void) {
    struct fs* fs = kmalloc(sizeof(struct fs));
    if (!fs)
        return ERR_PTR(-ENOMEM);
    *fs = (struct fs){.ref_count = 1};
    fs->cwd = vfs_get_root();
    if (IS_ERR(fs->cwd)) {
        kfree(fs);
        return ERR_CAST(fs->cwd);
    }
    return fs;
}

struct fs* fs_clone(struct fs* fs) {
    struct fs* new_fs = kmalloc(sizeof(struct fs));
    if (!new_fs)
        return ERR_PTR(-ENOMEM);
    *new_fs = (struct fs){.ref_count = 1};
    mutex_lock(&fs->lock);
    new_fs->cwd = path_dup(fs->cwd);
    mutex_unlock(&fs->lock);
    if (IS_ERR(new_fs->cwd)) {
        kfree(new_fs);
        return ERR_CAST(new_fs->cwd);
    }
    return new_fs;
}

void fs_ref(struct fs* fs) {
    ASSERT(fs);
    ++fs->ref_count;
}

void fs_unref(struct fs* fs) {
    if (!fs)
        return;
    ASSERT(fs->ref_count > 0);
    if (--fs->ref_count > 0)
        return;
    path_destroy_recursive(fs->cwd);
    kfree(fs);
}

static struct files* files_create(void) {
    struct files* files = kmalloc(sizeof(struct files));
    if (!files)
        return ERR_PTR(-ENOMEM);
    *files = (struct files){.ref_count = 1};
    return files;
}

struct files* files_clone(struct files* files) {
    struct files* new_files = files_create();
    if (IS_ERR(new_files))
        return new_files;

    mutex_lock(&files->lock);
    memcpy(new_files->entries, files->entries, sizeof(files->entries));
    for (size_t i = 0; i < OPEN_MAX; ++i) {
        if (files->entries[i])
            ++files->entries[i]->ref_count;
    }
    mutex_unlock(&files->lock);

    return new_files;
}

void files_ref(struct files* files) {
    ASSERT(files);
    ++files->ref_count;
}

void files_unref(struct files* files) {
    if (!files)
        return;
    ASSERT(files->ref_count > 0);
    if (--files->ref_count > 0)
        return;
    for (size_t i = 0; i < OPEN_MAX; ++i) {
        if (files->entries[i]) {
            file_close(files->entries[i]);
            files->entries[i] = NULL;
        }
    }
    kfree(files);
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
    *task = (struct task){.ref_count = 1};

    task->fpu_state = initial_fpu_state;
    task->state = TASK_RUNNING;
    strlcpy(task->comm, comm, sizeof(task->comm));

    int ret = 0;
    void* stack = NULL;

    task->fs = fs_create();
    if (IS_ERR(task->fs)) {
        ret = PTR_ERR(task->fs);
        task->fs = NULL;
        goto fail;
    }

    task->files = files_create();
    if (IS_ERR(task->files)) {
        ret = PTR_ERR(task->files);
        task->files = NULL;
        goto fail;
    }

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
    files_unref(task->files);
    fs_unref(task->fs);
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

    if (task->tid == 0) {
        // struct task is usually freed in a context of its parent task,
        // but the initial task is not a child of any task. Just leak it.
        return;
    }

    ASSERT(task != current);

    if (task->vm != kernel_vm)
        vm_unref(task->vm);
    files_unref(task->files);
    fs_unref(task->fs);
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

static noreturn void die(void) {
    if (current->tid == 1)
        PANIC("init task exited");

    sti();
    files_unref(current->files);
    current->files = NULL;
    fs_unref(current->fs);
    current->fs = NULL;

    cli();
    spinlock_lock(&all_tasks_lock);
    for (struct task* it = all_tasks; it; it = it->all_tasks_next) {
        // Orphaned child task is adopted by init task.
        if (it->ppid == current->tgid)
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
        kprintf("\x1b[31mTask %d exited with status %d\x1b[m\n", current->tid,
                status);
    current->exit_status = (status & 0xff) << 8;
    die();
}

static void terminate_with_signal(int signum) {
    kprintf("\x1b[31mTask %d was terminated with signal %d\x1b[m\n",
            current->tid, signum);
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

    int ret = 0;
    mutex_lock(&current->files->lock);

    if (fd >= 0) {
        struct file** entry = current->files->entries + fd;
        if (*entry) {
            ret = -EEXIST;
            goto done;
        }
        *entry = file;
        ret = fd;
        goto done;
    }

    ret = -EMFILE;
    struct file** it = current->files->entries;
    for (int i = 0; i < OPEN_MAX; ++i, ++it) {
        if (*it)
            continue;
        *it = file;
        ret = i;
        goto done;
    }

done:
    mutex_unlock(&current->files->lock);
    return ret;
}

int task_free_file_descriptor(int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return -EBADF;

    mutex_lock(&current->files->lock);
    struct file** file = current->files->entries + fd;
    if (!*file) {
        mutex_unlock(&current->files->lock);
        return -EBADF;
    }
    *file = NULL;
    mutex_unlock(&current->files->lock);
    return 0;
}

struct file* task_get_file(int fd) {
    if (fd < 0 || OPEN_MAX <= fd)
        return ERR_PTR(-EBADF);

    mutex_lock(&current->files->lock);
    struct file* file = current->files->entries[fd];
    mutex_unlock(&current->files->lock);
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

        int disp = get_default_disposition_for_signal(signum);
        switch (disp) {
        case DISP_TERM:
        case DISP_CORE:
            break;
        case DISP_IGN:
            continue;
        case DISP_STOP:
        case DISP_CONT:
            UNIMPLEMENTED();
        }

        it->pending_signals |= 1 << signum;

        if (it == current)
            task_handle_pending_signals();
    }
    spinlock_unlock(&all_tasks_lock);

    return found_dest ? 0 : -ESRCH;
}

void task_handle_pending_signals(void) {
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
