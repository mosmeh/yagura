#include <kernel/api/fcntl.h>
#include <kernel/console/console.h>
#include <kernel/cpu.h>
#include <kernel/device/device.h>
#include <kernel/drivers/drivers.h>
#include <kernel/drivers/serial.h>
#include <kernel/exec/exec.h>
#include <kernel/fs/file.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/multiboot.h>
#include <kernel/panic.h>
#include <kernel/sched.h>
#include <kernel/socket.h>
#include <kernel/syscall/syscall.h>
#include <kernel/task/task.h>
#include <kernel/time.h>

static void open_console(void) {
    struct file* file FREE(file) = vfs_open("/dev/console", O_RDWR, 0);
    if (IS_ERR(ASSERT(file))) {
        kprint("userland_init: unable to open an initial console\n");
        return;
    }
    int rc;
    for (int i = 0; i < 3; ++i)
        rc = files_alloc_fd(current->files, -1, file);
    (void)rc;
}

static noreturn void userland_init(void) {
    ASSERT(current->tid == 1);
    ASSERT(current->tgid == 1);
    ASSERT(current->pgid == 1);

    open_console();

    static const char* const envp[] = {"HOME=/", "TERM=linux", NULL};

    const char* init_path = cmdline_lookup("init");
    if (init_path) {
        const char* argv[] = {init_path, NULL};
        kprintf("userland_init: run %s as init process\n", init_path);
        int rc = execve_kernel(init_path, argv, envp);
        if (IS_ERR(rc)) {
            kprintf("userland_init: requested init %s failed (error %d)\n",
                    init_path, rc);
        }
    }

    static const char* const default_init_paths[] = {
        "/sbin/init",
        "/etc/init",
        "/bin/init",
        "/bin/sh",
    };
    for (size_t i = 0; i < ARRAY_SIZE(default_init_paths); ++i) {
        const char* path = default_init_paths[i];
        const char* argv[] = {path, NULL};
        kprintf("userland_init: run %s as init process\n", path);
        int rc = execve_kernel(path, argv, envp);
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

static const multiboot_info_t* mb_info;
static multiboot_module_t initrd_mod;

static noreturn void kernel_init(void) {
    ksyms_init();
    fs_init(&initrd_mod);
    device_init();
    drivers_init(mb_info);
    console_init();
    random_init();
    socket_init();
    time_init();
    syscall_init();
    smp_init();
    kprint("\x1b[32mkernel initialization done\x1b[m\n");

    ASSERT_OK(task_spawn("ksyncd", ksyncd));

    userland_init(); // Become the userland init process
}

noreturn void start(uint32_t mb_magic, uintptr_t mb_info_phys_addr) {
    gdt_init_cpu();
    cpu_init();
    idt_init();
    i8259_init();
    serial_early_init();
    kprint("\x1b[32mbooted\x1b[m\n"
           "version: " YAGURA_VERSION "\n");

    ASSERT(mb_magic == MULTIBOOT_BOOTLOADER_MAGIC);
    mb_info = (const void*)(mb_info_phys_addr + KERNEL_VIRT_ADDR);

    if (!(mb_info->flags & MULTIBOOT_INFO_MODS) || mb_info->mods_count == 0)
        PANIC("No initrd found. Provide initrd as the first Multiboot module");
    initrd_mod =
        *(const multiboot_module_t*)(mb_info->mods_addr + KERNEL_VIRT_ADDR);

    cmdline_init(mb_info);
    task_init();
    memory_init(mb_info);

    // Allow memory allocation that expects interrupts to be enabled
    enable_interrupts();

    ASSERT_OK(task_spawn("init", kernel_init));
    sched_start();
}
