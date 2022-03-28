#include "api/syscall.h"
#include "api/dirent.h"
#include "api/err.h"
#include "api/errno.h"
#include "api/fcntl.h"
#include "api/mman.h"
#include "asm_wrapper.h"
#include "boot_defs.h"
#include "fs/fs.h"
#include "interrupts.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "mem.h"
#include "panic.h"
#include "process.h"
#include "system.h"
#include <common/extra.h>
#include <common/string.h>
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
    if (params->length == 0 || params->offset < 0 ||
        !((params->flags & MAP_PRIVATE) ^ (params->flags & MAP_SHARED)))
        return -EINVAL;

    if (params->addr || !(params->prot & PROT_READ) || params->offset != 0)
        return -ENOTSUP;

    size_t length = round_up(params->length, PAGE_SIZE);

    uintptr_t vaddr = process_alloc_virtual_address_range(length);
    if (IS_ERR(vaddr))
        return vaddr;

    if (params->flags & MAP_ANONYMOUS) {
        if (params->flags & MAP_SHARED)
            return -ENOTSUP;

        int rc = mem_map_to_private_anonymous_region(
            vaddr, length, mem_prot_to_flags(params->prot));
        if (IS_ERR(rc))
            return rc;

        memset((void*)vaddr, 0, length);
        return vaddr;
    }

    if (params->flags & MAP_PRIVATE)
        return -ENOTSUP;

    file_description* desc = process_get_file_description(params->fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    if (desc->node->type == DT_DIR)
        return -ENODEV;

    return fs_mmap(desc, vaddr, length, params->prot, params->offset);
}

static uintptr_t sys_puts(const char* str) { return kputs(str); }

static uintptr_t sys_open(const char* pathname, int flags) {
    fs_node* node = vfs_open(pathname, flags);
    if (IS_ERR(node))
        return PTR_ERR(node);
    fs_open(node, flags);
    return process_alloc_file_descriptor(node);
}

static uintptr_t sys_close(int fd) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    fs_close(desc);
    return process_free_file_descriptor(fd);
}

static uintptr_t sys_read(int fd, void* buf, size_t count) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_read(desc, buf, count);
}

static uintptr_t sys_write(int fd, const void* buf, size_t count) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_write(desc, buf, count);
}

static uintptr_t sys_ioctl(int fd, int request, void* argp) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_ioctl(desc, request, argp);
}

static uintptr_t sys_getdents(int fd, void* dirp, size_t count) {
    file_description* desc = process_get_file_description(fd);
    if (IS_ERR(desc))
        return PTR_ERR(desc);
    return fs_readdir(desc, dirp, count);
}

typedef uintptr_t (*syscall_handler_fn)();

static syscall_handler_fn syscall_handlers[NUM_SYSCALLS + 1] = {
#define SYSCALL_HANDLER(name) sys_##name,
    ENUMERATE_SYSCALLS(SYSCALL_HANDLER)
#undef SYSCALL_HANDLER
        NULL};

static void syscall_handler(registers* regs) {
    KASSERT((regs->cs & 3) == 3);
    KASSERT((regs->ds & 3) == 3);
    KASSERT((regs->es & 3) == 3);
    KASSERT((regs->fs & 3) == 3);
    KASSERT((regs->gs & 3) == 3);
    KASSERT((regs->user_ss & 3) == 3);
    KASSERT(interrupts_enabled());

    if (regs->eax >= NUM_SYSCALLS) {
        regs->eax = -ENOSYS;
        return;
    }

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
