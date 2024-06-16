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
#include "string.h"
#include "time.h"

static noreturn void userland_init(void) {
    current->pid = current->pgid = process_generate_next_pid();

    const char* init_path = cmdline_lookup("init");
    if (!init_path)
        init_path = "/bin/init";

    const char* argv[] = {init_path, NULL};
    static const char* envp[] = {NULL};
    process_kernel_execve(init_path, argv, envp);
    PANIC("Failed to start init process");
}

extern unsigned char kernel_end[];
extern unsigned char stack_top[];

void start(uint32_t mb_magic, uintptr_t mb_info_paddr) {
    gdt_init();
    idt_init();
    irq_init();
    serial_early_init();
    kputs("\x1b[32mBooted\x1b[m\n");
    sti();

    ASSERT(mb_magic == MULTIBOOT_BOOTLOADER_MAGIC);
    kprintf("Kernel stack top: V0x%x\n", (uintptr_t)stack_top);
    kprintf("Kernel end: V0x%x\n", (uintptr_t)kernel_end);

    const multiboot_info_t* mb_info =
        (const multiboot_info_t*)(mb_info_paddr + KERNEL_VADDR);
    if (!(mb_info->flags & MULTIBOOT_INFO_MODS) || mb_info->mods_count == 0)
        PANIC("No initrd found. Provide initrd as the first Multiboot module");
    multiboot_module_t initrd_mod;
    memcpy(&initrd_mod,
           (const multiboot_module_t*)(mb_info->mods_addr + KERNEL_VADDR),
           sizeof(multiboot_module_t));

    cmdline_init(mb_info);
    paging_init(mb_info);
    vfs_init();
    process_init();
    scheduler_init();
    drivers_init(mb_info);
    vfs_populate_root_fs(&initrd_mod);
    random_init();
    console_init();
    time_init();
    syscall_init();
    kputs("\x1b[32mInitialization done\x1b[m\n");

    ASSERT_OK(process_spawn_kernel_process("userland_init", userland_init));

    process_exit(0);
}
