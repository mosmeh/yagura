#include "boot_defs.h"
#include "console/console.h"
#include "drivers/drivers.h"
#include "drivers/serial.h"
#include "interrupts.h"
#include "kprintf.h"
#include "memory/memory.h"
#include "multiboot.h"
#include "panic.h"
#include "process.h"
#include "scheduler.h"
#include "time.h"

static noreturn void userland_init(void) {
    current->pid = current->pgid = process_generate_next_pid();

    const char* init_path = cmdline_lookup("init");
    if (!init_path)
        init_path = "/bin/init";
    kprintf("userland_init: Starting %s\n", init_path);

    const char* argv[] = {init_path, NULL};
    static const char* envp[] = {NULL};
    process_kernel_execve(init_path, argv, envp);
    PANIC("Failed to start init process");
}

extern unsigned char kernel_end[];

noreturn void start(uint32_t mb_magic, uintptr_t mb_info_paddr) {
    gdt_init();
    idt_init();
    irq_init();
    serial_early_init();
    kputs("\x1b[32mbooted\x1b[m\n");
    sti();

    kprintf("version: %s\n"
            "kernel end: V0x%x\n",
            utsname()->version, (uintptr_t)kernel_end);
    ASSERT(mb_magic == MULTIBOOT_BOOTLOADER_MAGIC);

    const multiboot_info_t* mb_info =
        (const multiboot_info_t*)(mb_info_paddr + KERNEL_VADDR);
    if (!(mb_info->flags & MULTIBOOT_INFO_MODS) || mb_info->mods_count == 0)
        PANIC("No initrd found. Provide initrd as the first Multiboot module");
    multiboot_module_t initrd_mod =
        *(const multiboot_module_t*)(mb_info->mods_addr + KERNEL_VADDR);

    cmdline_init(mb_info);
    paging_init(mb_info);
    ksyms_init();
    vfs_init();
    process_init();
    scheduler_init();
    drivers_init(mb_info);
    vfs_populate_root_fs(&initrd_mod);
    random_init();
    console_init();
    time_init();
    syscall_init();
    kputs("\x1b[32mkernel initialization done\x1b[m\n");

    ASSERT_OK(process_spawn_kernel_process("userland_init", userland_init));

    process_exit(0);
}
