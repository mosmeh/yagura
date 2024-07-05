#include "boot_defs.h"
#include "console/console.h"
#include "drivers/drivers.h"
#include "drivers/serial.h"
#include "interrupts.h"
#include "kmsg.h"
#include "memory/memory.h"
#include "multiboot.h"
#include "panic.h"
#include "process.h"
#include "scheduler.h"
#include "time.h"

static noreturn void userland_init(void) {
    current->pid = current->pgid = process_generate_next_pid();

    static const char* envp[] = {NULL};

    const char* init_path = cmdline_lookup("init");
    if (init_path) {
        const char* argv[] = {init_path, NULL};
        kprintf("userland_init: run %s as init process\n", init_path);
        int rc = process_kernel_execve(init_path, argv, envp);
        if (IS_ERR(rc)) {
            kprintf("userland_init: requested init %s failed (error %d)\n",
                    init_path, rc);
        }
    }

    static const char* default_init_paths[] = {"/sbin/init", "/etc/init",
                                               "/bin/init", "/bin/sh"};
    for (size_t i = 0; i < ARRAY_SIZE(default_init_paths); ++i) {
        const char* argv[] = {default_init_paths[i], NULL};
        kprintf("userland_init: run %s as init process\n",
                default_init_paths[i]);
        int rc = process_kernel_execve(default_init_paths[i], argv, envp);
        if (rc != -ENOENT) {
            kprintf(
                "userland_init: %s exists but couldn't execute it (error %d)\n",
                default_init_paths[i], rc);
        }
    }

    PANIC("No working init found");
}

noreturn void start(uint32_t mb_magic, uintptr_t mb_info_phys_addr) {
    gdt_init();
    idt_init();
    irq_init();
    serial_early_init();
    kprint("\x1b[32mbooted\x1b[m\n");
    sti();

    kprintf("version: %s\n"
            "kernel end: V%p\n",
            utsname()->version, (void*)kernel_end);
    ASSERT(mb_magic == MULTIBOOT_BOOTLOADER_MAGIC);

    const multiboot_info_t* mb_info =
        (const multiboot_info_t*)(mb_info_phys_addr + KERNEL_VIRT_ADDR);
    if (!(mb_info->flags & MULTIBOOT_INFO_MODS) || mb_info->mods_count == 0)
        PANIC("No initrd found. Provide initrd as the first Multiboot module");
    multiboot_module_t initrd_mod =
        *(const multiboot_module_t*)(mb_info->mods_addr + KERNEL_VIRT_ADDR);

    cmdline_init(mb_info);
    memory_init(mb_info);
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
    kprint("\x1b[32mkernel initialization done\x1b[m\n");

    ASSERT_OK(process_spawn_kernel_process("userland_init", userland_init));

    process_exit(0);
}
