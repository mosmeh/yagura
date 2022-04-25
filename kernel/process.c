#include "process.h"
#include "boot_defs.h"
#include "interrupts.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "memory.h"
#include "memory/memory.h"
#include "panic.h"
#include "scheduler.h"
#include "system.h"
#include <common/extra.h>
#include <stdatomic.h>
#include <string.h>

#define USER_HEAP_START 0x100000

struct process* current;
const struct fpu_state initial_fpu_state;
static atomic_int next_pid;

extern unsigned char kernel_page_directory[];
extern unsigned char stack_top[];

void process_init(void) {
    __asm__ volatile("fninit");
    __asm__ volatile("fxsave %0"
                     : "=m"(*(struct fpu_state*)&initial_fpu_state));

    atomic_init(&next_pid, 1);

    current = kaligned_alloc(alignof(struct process), sizeof(struct process));
    ASSERT(current);
    *current = (struct process){0};
    current->id = 0;
    current->fpu_state = initial_fpu_state;
    current->pd =
        (page_directory*)((uintptr_t)kernel_page_directory + KERNEL_VADDR);
    current->stack_top = (uintptr_t)stack_top;
    range_allocator_init(&current->vaddr_allocator, USER_HEAP_START,
                         KERNEL_VADDR);
    current->cwd = kstrdup(ROOT_DIR);
    ASSERT(current->cwd);
    ASSERT_OK(file_descriptor_table_init(&current->fd_table));
    current->next = NULL;

    gdt_set_kernel_stack(current->stack_top);
}

struct process* process_create_kernel_process(void (*entry_point)(void)) {
    struct process* process =
        kaligned_alloc(alignof(struct process), sizeof(struct process));
    if (!process)
        return ERR_PTR(-ENOMEM);
    *process = (struct process){0};

    process->id = 0;
    process->eip = (uintptr_t)entry_point;
    process->fpu_state = initial_fpu_state;
    range_allocator_init(&process->vaddr_allocator, USER_HEAP_START,
                         KERNEL_VADDR);

    process->pd = memory_create_page_directory();
    if (IS_ERR(process->pd))
        return ERR_CAST(process->pd);

    process->cwd = kstrdup(ROOT_DIR);
    if (!process->cwd)
        return ERR_PTR(-ENOMEM);

    int rc = file_descriptor_table_init(&process->fd_table);
    if (IS_ERR(rc))
        return ERR_PTR(rc);

    void* stack = kmalloc(STACK_SIZE);
    if (!stack)
        return ERR_PTR(-ENOMEM);
    process->stack_top = (uintptr_t)stack + STACK_SIZE;
    process->esp = process->ebp = process->stack_top;

    return process;
}

pid_t process_spawn_kernel_process(void (*entry_point)(void)) {
    struct process* process = process_create_kernel_process(entry_point);
    if (IS_ERR(process))
        return PTR_ERR(process);
    scheduler_enqueue(process);
    return process->id;
}

pid_t process_generate_next_pid(void) {
    return atomic_fetch_add_explicit(&next_pid, 1, memory_order_acq_rel);
}

noreturn void process_exit(int status) {
    ASSERT(interrupts_enabled());

    if (status != 0)
        kprintf("\x1b[31mProcess %d exited with status %d\x1b[m\n", current->id,
                status);

    if (current->id == 1)
        PANIC("init process exited");

    file_description** it = current->fd_table.entries;
    for (int i = 0; i < OPEN_MAX; ++i, ++it) {
        if (*it)
            fs_close(*it);
    }

    memory_destroy_current_page_directory();

    kfree(current->cwd);
    range_allocator_destroy(&current->vaddr_allocator);

    scheduler_yield(false);
    UNREACHABLE();
}

void process_tick(bool in_kernel) {
    if (in_kernel)
        ++current->kernel_ticks;
    else
        ++current->user_ticks;
}

int process_alloc_file_descriptor(int fd, file_description* desc) {
    if (fd >= OPEN_MAX)
        return -EBADF;

    if (fd >= 0) {
        file_description** entry = current->fd_table.entries + fd;
        if (*entry)
            return -EEXIST;
        *entry = desc;
        return fd;
    }

    file_description** it = current->fd_table.entries;
    for (int i = 0; i < OPEN_MAX; ++i, ++it) {
        if (*it)
            continue;
        *it = desc;
        return i;
    }
    return -EMFILE;
}

int process_free_file_descriptor(int fd) {
    if (fd >= OPEN_MAX)
        return -EBADF;

    file_description** desc = current->fd_table.entries + fd;
    if (!*desc)
        return -EBADF;
    *desc = NULL;
    return 0;
}

file_description* process_get_file_description(int fd) {
    if (fd >= OPEN_MAX)
        return ERR_PTR(-EBADF);

    file_description** desc = current->fd_table.entries + fd;
    if (!*desc)
        return ERR_PTR(-EBADF);

    return *desc;
}
