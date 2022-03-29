#include "boot_defs.h"
#include "interrupts.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "mem.h"
#include "multiboot.h"
#include "panic.h"
#include "process.h"
#include "serial.h"
#include "system.h"
#include <kernel/api/err.h>

void userland_main(void);

static noreturn void kernel_process_entry(void) {
    process_enter_userland(userland_main);
    KUNREACHABLE();
}

extern unsigned char kernel_end[];
extern unsigned char stack_top[];

void start(uint32_t mb_magic, uintptr_t mb_info_paddr) {
    gdt_init();
    idt_init();
    irq_init();
    serial_init();
    kprintf("\n\x1b[32mBooted\x1b[m\n");
    sti();

    KASSERT(mb_magic == MULTIBOOT_BOOTLOADER_MAGIC);
    kprintf("Kernel stack top: V0x%x\n", (uintptr_t)stack_top);
    kprintf("Kernel end: V0x%x\n", (uintptr_t)kernel_end);

    const multiboot_info_t* mb_info =
        (const multiboot_info_t*)(mb_info_paddr + KERNEL_VADDR);
    mem_init(mb_info);
    kmalloc_init();

    ps2_mouse_init();
    bochs_graphics_init();

    vfs_init();
    const multiboot_module_t* initrd_mod =
        (const multiboot_module_t*)(mb_info->mods_addr + KERNEL_VADDR);
    initrd_init(initrd_mod->mod_start + KERNEL_VADDR);

    vfs_mount("/", initrd_create());
    vfs_mount("/dev/ttyS0", serial_device_create(SERIAL_COM1));
    vfs_mount("/dev/ttyS1", serial_device_create(SERIAL_COM2));
    vfs_mount("/dev/ttyS2", serial_device_create(SERIAL_COM3));
    vfs_mount("/dev/ttyS3", serial_device_create(SERIAL_COM4));
    vfs_mount("/dev/fb0", bochs_graphics_device_create());
    vfs_mount("/dev/psaux", ps2_mouse_device_create());
    vfs_mount("/tmp", tmpfs_create());
    vfs_mount("/foo/bar/baz", initrd_create());

    syscall_init();
    process_init();
    pit_init(UINT32_MAX);
    kprintf("\x1b[32mInitialization done\x1b[m\n");

    KASSERT(IS_OK(process_spawn_kernel_process(kernel_process_entry)));

    process_exit(0);
}
