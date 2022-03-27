#include "asm_wrapper.h"
#include "boot_defs.h"
#include "fs/fs.h"
#include "graphics.h"
#include "hid.h"
#include "interrupts.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "mem.h"
#include "multiboot.h"
#include "process.h"
#include "serial.h"
#include "system.h"
#include <common/extra.h>
#include <common/string.h>
#include <common/syscall.h>
#include <common/types.h>
#include <userland/stdlib.h>
#include <userland/syscall.h>

static noreturn void userland_entry(void) {
    pid_t pid_before = getpid();
    ASSERT(pid_before >= 0);

    pid_t ret = fork();
    ASSERT(ret >= 0);
    pid_t pid_after = getpid();
    ASSERT(pid_after >= 0);

    if (ret == 0) {
        ASSERT(pid_after > pid_before);
    } else {
        ASSERT(pid_after == pid_before);
        ASSERT(ret > pid_before);
    }

    malloc_ctx ctx;
    malloc_init(&ctx);

    const size_t size = PAGE_SIZE * 2 + 128;
    void* buf = malloc(&ctx, size);
    memset(buf, 42, size);
    ASSERT(buf);
    free(&ctx, buf);

    exit(0);
}

static void read_file(const char* filename) {
    int fd = open(filename, O_RDWR);
    ASSERT(fd >= 0);
    const size_t size = 1024;
    char buf[size];
    ssize_t nread = read(fd, buf, size);
    ASSERT(nread >= 0);
    ASSERT(close(fd) >= 0);
}

static noreturn void userland_entry2(void) {
    read_file("/hello.txt");
    read_file("/foo/bar/baz/foo.txt");

    int fd = open("/dev/ttyS1", O_RDWR);
    ASSERT(fd >= 0);
    ASSERT(close(fd) >= 0);

    int fb_fd = open("/dev/fb0", O_RDWR);
    ASSERT(fb_fd >= 0);
    fb_info info;
    ASSERT(ioctl(fb_fd, FBIOGET_INFO, &info) >= 0);
    uint32_t* fb =
        (uint32_t*)mmap(NULL, info.pitch * info.height, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fb_fd, 0);
    ASSERT(fb != MAP_FAILED);
    for (size_t y = 0; y < info.height; ++y)
        for (size_t x = 0; x < info.width; ++x)
            fb[x + info.width * y] =
                ((100000 * x / (info.width - 1) / 1000) << 16) +
                ((100000 * y / (info.height - 1) / 1000) << 8);

    int ps_fd = open("/dev/psaux", O_RDWR);
    int32_t x = info.width / 2;
    int32_t y = info.height / 2;
    mouse_packet packet;
    for (;;) {
        ssize_t nread = read(ps_fd, &packet, sizeof(mouse_packet));
        if (nread == 0)
            continue;
        ASSERT(nread == sizeof(mouse_packet));
        x = MIN((int32_t)(info.width - 1), MAX(0, x + packet.dx));
        y = MIN((int32_t)(info.height - 1), MAX(0, y - packet.dy));
        fb[x + info.width * y] =
            (packet.buttons & MOUSE_BUTTON_LEFT) ? 0xff0000 : 0xffffff;
    }

    ASSERT(close(fb_fd) >= 0);
    ASSERT(close(ps_fd) >= 0);

    exit(123);
}

static noreturn void kernel_process_entry2(void) {
    process_enter_userland(userland_entry2);
    process_exit(1);
}

static noreturn void kernel_process_entry(void) {
    pid_t pid = process_get_pid();
    KASSERT(pid >= 0);
    process_spawn_kernel_process(kernel_process_entry2);
    process_enter_userland(userland_entry);
    process_exit(1);
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
    vfs_mount("/foo/bar/baz", initrd_create());
    vfs_mount("/dev/ttyS0", serial_device_create(SERIAL_COM1));
    vfs_mount("/dev/ttyS1", serial_device_create(SERIAL_COM2));
    vfs_mount("/dev/ttyS2", serial_device_create(SERIAL_COM3));
    vfs_mount("/dev/ttyS3", serial_device_create(SERIAL_COM4));
    vfs_mount("/dev/fb0", bochs_graphics_device_create());
    vfs_mount("/dev/psaux", ps2_mouse_device_create());

    syscall_init();
    process_init();
    pit_init(UINT32_MAX);
    kprintf("\x1b[32mInitialization done\x1b[m\n");

    pid_t ret = process_spawn_kernel_process(kernel_process_entry);
    KASSERT(ret >= 0);

    process_exit(0);
}
