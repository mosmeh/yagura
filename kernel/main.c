#include "api/sys/stat.h"
#include "boot_defs.h"
#include "console/console.h"
#include "graphics/graphics.h"
#include "hid/hid.h"
#include "interrupts.h"
#include "kprintf.h"
#include "memory.h"
#include "memory/memory.h"
#include "multiboot.h"
#include "panic.h"
#include "process.h"
#include "scheduler.h"
#include "serial.h"
#include "syscall/syscall.h"
#include "system.h"

static noreturn void init(void) {
    current->pid = current->pgid = process_generate_next_pid();

    static char* argv[] = {NULL};
    static char* envp[] = {NULL};
    const char* init_path = cmdline_get("init");
    if (!init_path)
        init_path = "/bin/init";
    ASSERT_OK(sys_execve(init_path, argv, envp));
    UNREACHABLE();
}

extern unsigned char kernel_end[];
extern unsigned char stack_top[];

static void create_char_device(const char* pathname, struct file* device_file) {
    ASSERT_OK(vfs_register_device(device_file));
    ASSERT_OK(sys_mknod(pathname, S_IFCHR, device_file->device_id));
}

void start(uint32_t mb_magic, uintptr_t mb_info_paddr) {
    gdt_init();
    idt_init();
    irq_init();
    bool com1_is_available = serial_enable_port(SERIAL_COM1);
    kprintf("\x1b[32mBooted\x1b[m\n");
    sti();

    ASSERT(mb_magic == MULTIBOOT_BOOTLOADER_MAGIC);
    kprintf("Kernel stack top: V0x%x\n", (uintptr_t)stack_top);
    kprintf("Kernel end: V0x%x\n", (uintptr_t)kernel_end);

    const multiboot_info_t* mb_info =
        (const multiboot_info_t*)(mb_info_paddr + KERNEL_VADDR);

    cmdline_init(mb_info);

    const multiboot_module_t* initrd_mod =
        (const multiboot_module_t*)(mb_info->mods_addr + KERNEL_VADDR);
    uintptr_t initrd_paddr = initrd_mod->mod_start;
    uintptr_t initrd_size = initrd_mod->mod_end - initrd_mod->mod_start;

    paging_init(mb_info);
    process_init();

    ASSERT_OK(vfs_mount(ROOT_DIR, tmpfs_create_root()));

    initrd_populate_root_fs(initrd_paddr, initrd_size);

    ASSERT_OK(vfs_mount("/tmp", tmpfs_create_root()));
    ASSERT_OK(vfs_mount("/dev/shm", tmpfs_create_root()));

    create_char_device("/dev/null", null_device_create());
    create_char_device("/dev/zero", zero_device_create());
    create_char_device("/dev/full", full_device_create());

    ps2_init();
    create_char_device("/dev/kbd", ps2_keyboard_device_create());
    create_char_device("/dev/psaux", ps2_mouse_device_create());

    if (fb_init(mb_info)) {
        create_char_device("/dev/fb0", fb_device_create());
        fb_console_init();
        create_char_device("/dev/tty", fb_console_device_create());
    }

    if (com1_is_available)
        create_char_device("/dev/ttyS0", serial_device_create(SERIAL_COM1));
    if (serial_enable_port(SERIAL_COM2))
        create_char_device("/dev/ttyS1", serial_device_create(SERIAL_COM2));
    if (serial_enable_port(SERIAL_COM2))
        create_char_device("/dev/ttyS2", serial_device_create(SERIAL_COM3));
    if (serial_enable_port(SERIAL_COM3))
        create_char_device("/dev/ttyS3", serial_device_create(SERIAL_COM4));

    system_console_init();
    create_char_device("/dev/console", system_console_device_create());

    syscall_init();
    scheduler_init();
    time_init();
    pit_init();
    kprintf("\x1b[32mInitialization done\x1b[m\n");

    ASSERT_OK(process_spawn_kernel_process(init));

    process_exit(0);
}
