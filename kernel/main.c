#include "asm_wrapper.h"
#include "boot_defs.h"
#include "fs/fs.h"
#include "interrupts.h"
#include "kernel/graphics/graphics.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "mem.h"
#include "multiboot.h"
#include "process.h"
#include "serial.h"
#include "system.h"
#include <common/string.h>
#include <common/syscall.h>
#include <common/types.h>
#include <userland/stdlib.h>
#include <userland/syscall.h>

static noreturn void userland_entry(void) {
    printf("[%d] Entered userland\n", getpid());

    pid_t ret = fork();
    pid_t pid = getpid();
    uint32_t esp;
    __asm__ volatile("mov %%esp, %0" : "=r"(esp));

    if (ret == 0)
        printf("[%d] I'm a userland child! fork()=%d esp=0x%x eip=0x%x\n", pid,
               ret, esp, read_eip());
    else
        printf("[%d] I'm a userland parent! fork()=%d esp=0x%x eip=0x%x\n", pid,
               ret, esp, read_eip());

    malloc_ctx ctx;
    malloc_init(&ctx);

    size_t size = PAGE_SIZE * 2 + 128;
    size_t len = size / sizeof(uint32_t);
    uint32_t* buf = (uint32_t*)malloc(&ctx, size);
    printf("[%d] buf=0x%x\n", pid, buf);
    for (size_t i = 0; i < len; ++i)
        buf[i] = pid + 10;
    size_t sum = 0;
    for (size_t i = 0; i < len; ++i)
        sum += buf[i];
    free(&ctx, buf);
    printf("[%d] sum=%u\n", pid, sum);

    for (int i = 0; i < 5; ++i)
        printf("[%d] %d\n", pid, i);

    exit(0);
}

static void dump_file(const char* filename) {
    int fd = open(filename, O_RDWR);
    printf("fd = %d\n", fd);
    size_t buflen = 1024;
    char buf[buflen];
    ssize_t nread = read(fd, buf, buflen);
    ASSERT(nread >= 0);
    size_t len = (size_t)nread;
    printf("len = %d\n", len);
    buf[len < buflen - 1 ? len : buflen - 1] = '\0';
    printf("_%s_\n", buf);
    close(fd);
}

static noreturn void userland_entry2(void) {
    dump_file("/hello.txt");
    dump_file("/foo/bar/baz/foo.txt");

    {
        int fd = open("/dev/ttyS1", O_RDWR);
        char buf[1024];
        int len = sprintf(buf, "[%d] hello, COM2\n", getpid());
        write(fd, buf, len);
        close(fd);
    }
    {
        int fd = open("/dev/fb0", O_RDWR);
        fb_resolution r;
        {
            ioctl(fd, FBIOGET_RESOLUTION, &r);
            printf("FB get: %ux%u (pitch=%u)\n", r.width, r.height, r.pitch);
        }
        {
            r.width = 10000;
            r.height = 10000;
            ioctl(fd, FBIOSET_RESOLUTION, &r);
            printf("FB set: %ux%u (pitch=%u)\n", r.width, r.height, r.pitch);
        }
        {
            uint32_t* fb =
                (uint32_t*)mmap(NULL, r.pitch * r.height,
                                PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            ASSERT(fb != MAP_FAILED);
            for (size_t y = 0; y < r.height; ++y)
                for (size_t x = 0; x < r.width; ++x)
                    fb[x + r.width * y] =
                        ((255999 * x / (r.width - 1) / 1000) << 16) +
                        ((255999 * y / (r.height - 1) / 1000) << 8) + 0x3f;
        }
        close(fd);
    }

    exit(123);
}

static noreturn void kernel_process_entry2(void) {
    uint32_t esp;
    __asm__ volatile("mov %%esp, %0" : "=r"(esp));
    kprintf("[%d] I'm a brand new kernel process esp=0x%x\n", process_get_pid(),
            esp);
    kprintf("[%d] Entering userland...\n");
    process_enter_userland(userland_entry2);
    process_exit(1);
}

static noreturn void kernel_process_entry(void) {
    pid_t pid = process_get_pid();
    uint32_t esp;
    __asm__ volatile("mov %%esp, %0" : "=r"(esp));
    kprintf("[%d] I'm a new kernel process esp=0x%x\n", pid, esp);
    process_spawn_kernel_process(kernel_process_entry2);
    kprintf("[%d] Entering userland...\n");
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

    syscall_init();
    process_init();
    pit_init(UINT32_MAX);
    kprintf("\x1b[32mInitialization done\x1b[m\n");

    pid_t ret = process_spawn_kernel_process(kernel_process_entry);
    kprintf("[%d] I'm the first process ret=%d\n", process_get_pid(), ret);

    process_exit(0);
}
