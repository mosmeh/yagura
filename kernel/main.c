#include "acpi.h"
#include "api/fcntl.h"
#include "console/console.h"
#include "cpu.h"
#include "device/device.h"
#include "drivers/drivers.h"
#include "drivers/serial.h"
#include "interrupts/interrupts.h"
#include "kmsg.h"
#include "memory/memory.h"
#include "multiboot.h"
#include "panic.h"
#include "sched.h"
#include "socket.h"
#include "task.h"
#include "time.h"

static void open_console(void) {
    struct file* file FREE(file) = vfs_open("/dev/console", O_RDWR, 0);
    if (IS_ERR(file)) {
        kprint("userland_init: unable to open an initial console\n");
        return;
    }
    int rc;
    for (int i = 0; i < 3; ++i)
        rc = task_alloc_fd(-1, file);
    (void)rc;
}

static noreturn void userland_init(void) {
    ASSERT(current->tid == 1);
    ASSERT(current->tgid == 1);
    ASSERT(current->pgid == 1);

    open_console();

    static const char* envp[] = {"HOME=/", "TERM=linux", NULL};

    const char* init_path = cmdline_lookup("init");
    if (init_path) {
        const char* argv[] = {init_path, NULL};
        kprintf("userland_init: run %s as init process\n", init_path);
        int rc = task_kernel_execve(init_path, argv, envp);
        if (IS_ERR(rc)) {
            kprintf("userland_init: requested init %s failed (error %d)\n",
                    init_path, rc);
        }
    }

    static const char* default_init_paths[] = {
        "/sbin/init",
        "/etc/init",
        "/bin/init",
        "/bin/sh",
    };
    for (size_t i = 0; i < ARRAY_SIZE(default_init_paths); ++i) {
        const char* path = default_init_paths[i];
        const char* argv[] = {path, NULL};
        kprintf("userland_init: run %s as init process\n", path);
        int rc = task_kernel_execve(path, argv, envp);
        if (rc != -ENOENT) {
            kprintf(
                "userland_init: %s exists but couldn't execute it (error %d)\n",
                path, rc);
        }
    }

    PANIC("No working init found");
}

static noreturn void ksyncd(void) {
    static const struct timespec interval = {.tv_sec = 5};
    for (;;) {
        int rc = vfs_sync();
        if (IS_ERR(rc))
            kprintf("ksyncd: sync failed (error %d)\n", rc);
        sched_sleep(&interval);
    }
}

noreturn void start(uint32_t mb_magic, uintptr_t mb_info_phys_addr) {
    gdt_init_cpu();
    cpu_init();
    idt_init();
    i8259_init();
    serial_early_init();
    kprint("\x1b[32mbooted\x1b[m\n");
    sti();

    struct utsname utsname;
    utsname_get(&utsname);
    kprintf("version: %s\n"
            "kernel end: V%p\n",
            utsname.version, (void*)kernel_end);
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
    task_init();
    acpi_init();
    time_init();
    device_init();
    fs_init(&initrd_mod);
    drivers_init(mb_info);
    smp_init();
    random_init();
    console_init();
    socket_init();
    syscall_init();
    sched_init();
    smp_start();
    kprint("\x1b[32mkernel initialization done\x1b[m\n");

    ASSERT_OK(task_spawn("userland_init", userland_init));
    ASSERT_OK(task_spawn("ksyncd", ksyncd));

    sched_start();
}
