#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/stat.h>
#include <kernel/api/time.h>
#include <kernel/api/times.h>
#include <kernel/boot_defs.h>
#include <kernel/kmalloc.h>
#include <kernel/memory/memory.h>
#include <kernel/process.h>
#include <kernel/scheduler.h>
#include <kernel/system.h>
#include <string.h>

noreturn uintptr_t sys_exit(int status) { process_exit(status); }

uintptr_t sys_getpid(void) { return current->id; }

uintptr_t sys_yield(void) {
    scheduler_yield(true);
    return 0;
}

void return_to_userland(registers);

uintptr_t sys_fork(registers* regs) {
    process* p = kaligned_alloc(alignof(process), sizeof(process));
    if (!p)
        return -ENOMEM;
    *p = (process){0};

    p->pd = memory_clone_current_page_directory();
    if (IS_ERR(p->pd))
        return PTR_ERR(p->pd);

    p->id = process_generate_next_pid();
    p->eip = (uintptr_t)return_to_userland;
    p->ebx = current->ebx;
    p->esi = current->esi;
    p->edi = current->edi;
    p->fpu_state = current->fpu_state;

    p->heap_next_vaddr = current->heap_next_vaddr;

    p->user_ticks = current->user_ticks;
    p->kernel_ticks = current->kernel_ticks;

    p->cwd = kstrdup(current->cwd);
    if (!p->cwd)
        return -ENOMEM;

    int rc = file_descriptor_table_clone_from(&p->fd_table, &current->fd_table);
    if (IS_ERR(rc))
        return rc;

    void* stack = kmalloc(STACK_SIZE);
    if (!stack)
        return -ENOMEM;
    p->stack_top = (uintptr_t)stack + STACK_SIZE;
    p->esp = p->ebp = p->stack_top;

    // push the argument of return_to_userland()
    p->esp -= sizeof(registers);
    registers* child_regs = (registers*)p->esp;
    *child_regs = *regs;
    child_regs->eax = 0; // fork() returns 0 in the child

    scheduler_enqueue(p);

    return p->id;
}

static bool waitpid_should_unblock(const pid_t* pid) {
    return !scheduler_find_process_by_pid(*pid);
}

// NOLINTNEXTLINE(readability-non-const-parameter)
pid_t sys_waitpid(pid_t pid, int* wstatus, int options) {
    if (pid <= 0 || wstatus || options != 0)
        return -ENOTSUP;
    scheduler_block(waitpid_should_unblock, &pid);
    return pid;
}

uintptr_t sys_times(struct tms* buf) {
    buf->tms_utime = current->user_ticks;
    buf->tms_stime = current->kernel_ticks;
    return uptime;
}

static bool sleep_should_unblock(const uint32_t* deadline) {
    return uptime >= *deadline;
}

uintptr_t sys_nanosleep(const struct timespec* req, struct timespec* rem) {
    uint32_t deadline = uptime + req->tv_sec * CLOCKS_PER_SEC +
                        req->tv_nsec * CLOCKS_PER_SEC / 1000000000;
    scheduler_block(sleep_should_unblock, &deadline);
    if (rem)
        rem->tv_sec = rem->tv_nsec = 0;
    return 0;
}

uintptr_t sys_getcwd(char* buf, size_t size) {
    if (!buf || size == 0)
        return -EINVAL;
    if (size < strlen(current->cwd) + 1)
        return -ERANGE;
    strlcpy(buf, current->cwd, size);
    return (uintptr_t)buf;
}

uintptr_t sys_chdir(const char* path) {
    struct file* file = vfs_resolve_path(path, current->cwd, NULL, NULL);
    if (IS_ERR(file))
        return PTR_ERR(file);
    if (!S_ISDIR(file->mode))
        return -ENOTDIR;
    current->cwd = vfs_canonicalize_path(path, current->cwd);
    return 0;
}
