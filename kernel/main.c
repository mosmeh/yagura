#include "api/stat.h"
#include "boot_defs.h"
#include "console/console.h"
#include "hid/hid.h"
#include "interrupts.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "mem.h"
#include "multiboot.h"
#include "panic.h"
#include "process.h"
#include "scheduler.h"
#include "serial.h"
#include "syscall/syscall.h"

static noreturn void init(void) {
    static char* argv[] = {NULL};
    static char* envp[] = {NULL};
    ASSERT_OK(sys_execve("/bin/init", argv, envp));
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
    ASSERT(serial_enable_port(SERIAL_COM1));
    kprintf("\x1b[32mBooted\x1b[m\n");
    sti();

    ASSERT(mb_magic == MULTIBOOT_BOOTLOADER_MAGIC);
    kprintf("Kernel stack top: V0x%x\n", (uintptr_t)stack_top);
    kprintf("Kernel end: V0x%x\n", (uintptr_t)kernel_end);

    const multiboot_info_t* mb_info =
        (const multiboot_info_t*)(mb_info_paddr + KERNEL_VADDR);
    mem_init(mb_info);
    kmalloc_init();
    process_init();

    ps2_init();
    bochs_graphics_init();

    ASSERT_OK(vfs_mount(ROOT_DIR, tmpfs_create_root()));

    const multiboot_module_t* initrd_mod =
        (const multiboot_module_t*)(mb_info->mods_addr + KERNEL_VADDR);
    initrd_populate_root_fs(initrd_mod->mod_start + KERNEL_VADDR);

    ASSERT_OK(vfs_mount("/tmp", tmpfs_create_root()));
    ASSERT_OK(vfs_mount("/dev/shm", shmfs_create_root()));

    create_char_device("/dev/kbd", ps2_keyboard_device_create());
    create_char_device("/dev/psaux", ps2_mouse_device_create());
    create_char_device("/dev/fb0", bochs_graphics_device_create());

    tty_init();
    create_char_device("/dev/tty", tty_device_create());

    create_char_device("/dev/ttyS0", serial_device_create(SERIAL_COM1));
    if (serial_enable_port(SERIAL_COM2))
        create_char_device("/dev/ttyS1", serial_device_create(SERIAL_COM2));
    if (serial_enable_port(SERIAL_COM2))
        create_char_device("/dev/ttyS2", serial_device_create(SERIAL_COM3));
    if (serial_enable_port(SERIAL_COM3))
        create_char_device("/dev/ttyS3", serial_device_create(SERIAL_COM4));

    syscall_init();
    scheduler_init();
    pit_init();
    kprintf("\x1b[32mInitialization done\x1b[m\n");

    ASSERT_OK(process_spawn_kernel_process(init));

    process_exit(0);
}
