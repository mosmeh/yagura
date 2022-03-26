#include "asm_wrapper.h"
#include "boot_defs.h"
#include "fs/fs.h"
#include "interrupts.h"
#include "kprintf.h"
#include "mem.h"
#include "process.h"
#include "system.h"
#include <common/extra.h>
#include <common/string.h>
#include <common/syscall.h>
#include <stdint.h>
#include <stdnoreturn.h>

noreturn static uintptr_t sys_exit(int status) { process_exit(status); }

static uintptr_t sys_fork(registers* regs) {
    return process_userland_fork(regs);
}

static uintptr_t sys_getpid(void) { return process_get_pid(); }

static uintptr_t sys_yield(void) {
    process_switch();
    return 0;
}

noreturn static uintptr_t sys_halt(void) {
    kprintf("System halted\n");
    cli();
    for (;;)
        hlt();
}

static uintptr_t sys_mmap(const mmap_params* params) {
    KASSERT(params->addr == NULL);
    KASSERT(params->length > 0);
    KASSERT(params->flags == (MAP_PRIVATE | MAP_ANONYMOUS));
    KASSERT(params->fd == 0);
    KASSERT(params->offset == 0);

    uintptr_t current_ptr = current->heap_next_vaddr;
    uintptr_t aligned_ptr = round_up(current_ptr, PAGE_SIZE);
    uintptr_t next_ptr = aligned_ptr + params->length;
    KASSERT(next_ptr <= USER_STACK_BASE - PAGE_SIZE);

    uint32_t flags = MEM_USER;
    if (params->prot & PROT_WRITE)
        flags |= MEM_WRITE;
    mem_map_virtual_addr_range_to_any_pages(aligned_ptr, next_ptr, flags);
    memset((void*)aligned_ptr, 0, params->length);

    current->heap_next_vaddr = next_ptr;
    return aligned_ptr;
}

static uintptr_t sys_puts(const char* str) { return kputs(str); }

static uintptr_t sys_open(const char* pathname, int flags) {
    fs_node* node = vfs_find_by_pathname(pathname);
    fs_open(node, flags);
    return process_alloc_file_descriptor(node);
}

static uintptr_t sys_close(int fd) {
    file_description* entry = current->fd_table.entries + fd;
    fs_close(entry->node);
    process_free_file_descriptor(fd);
    return 0;
}

static uintptr_t sys_read(int fd, void* buf, size_t count) {
    file_description* entry = current->fd_table.entries + fd;
    size_t nread = fs_read(entry->node, entry->offset, count, buf);
    entry->offset += nread;
    return nread;
}

static uintptr_t sys_write(int fd, const void* buf, size_t count) {
    file_description* entry = current->fd_table.entries + fd;
    size_t nwrittern = fs_write(entry->node, entry->offset, count, buf);
    entry->offset += nwrittern;
    return nwrittern;
}

typedef uintptr_t (*syscall_handler_fn)();

static syscall_handler_fn syscall_handlers[NUM_SYSCALLS + 1] = {
#define SYSCALL_HANDLER(name) sys_##name,
    ENUMERATE_SYSCALLS(SYSCALL_HANDLER)
#undef SYSCALL_HANDLER
        NULL};

static void syscall_handler(registers* regs) {
    KASSERT(interrupts_enabled());
    KASSERT(regs->eax < NUM_SYSCALLS);

    syscall_handler_fn handler = syscall_handlers[regs->eax];
    KASSERT(handler);

    if (regs->eax == SYS_fork)
        regs->eax = handler(regs);
    else
        regs->eax = handler(regs->edx, regs->ecx, regs->ebx);
}

void syscall_init(void) {
    idt_register_interrupt_handler(SYSCALL_VECTOR, syscall_handler);
    idt_set_gate_user_callable(SYSCALL_VECTOR);
    idt_flush();
}
