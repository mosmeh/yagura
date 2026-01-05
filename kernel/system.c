#include <common/stdlib.h>
#include <common/string.h>
#include <kernel/cpu.h>
#include <kernel/drivers/hid/ps2.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>
#include <kernel/system.h>
#include <stdarg.h>

static struct utsname utsname = {
    .sysname = "yagura",
    .nodename = "(none)",
    .release = "dev",
    .version = YAGURA_VERSION,
    .machine = "x86_64",
    .domainname = "(none)",
};

static struct mutex utsname_lock;

void utsname_get(struct utsname* buf) {
    SCOPED_LOCK(mutex, &utsname_lock);
    *buf = utsname;
}

int utsname_set_hostname(const char* hostname, size_t len) {
    if (len >= sizeof(utsname.nodename))
        return -EINVAL;
    SCOPED_LOCK(mutex, &utsname_lock);
    strlcpy(utsname.nodename, hostname, len + 1);
    return 0;
}

int utsname_set_domainname(const char* domainname, size_t len) {
    if (len >= sizeof(utsname.domainname))
        return -EINVAL;
    SCOPED_LOCK(mutex, &utsname_lock);
    strlcpy(utsname.domainname, domainname, len + 1);
    return 0;
}

noreturn void reboot(void) {
    out8(PS2_COMMAND, 0xfe);
    halt();
}

noreturn void halt(void) {
    disable_interrupts();
    if (smp_active)
        cpu_broadcast_message_coalesced(IPI_MESSAGE_HALT, true);
    for (;;)
        hlt();
}

noreturn void poweroff(void) {
    // this works only on emulators
    out16(0x604, 0x2000);  // QEMU
    out16(0x4004, 0x3400); // Virtualbox
    out16(0xb004, 0x2000); // Bochs and older versions of QEMU
    halt();
}

static void dump_registers(const struct registers* regs) {
    kprintf("interrupt_num=%lu error_code=0x%016lx\n"
            "   pc=0x%04lx:0x%016lx rflags=0x%016lx\n"
            "stack=0x%04lx:0x%016lx\n"
            "  rax=0x%016lx rbx=0x%016lx rcx=0x%016lx rdx=0x%016lx\n"
            "  rbp=0x%016lx rsi=0x%016lx rdi=0x%016lx\n"
            "   r8=0x%016lx  r9=0x%016lx r10=0x%016lx r11=0x%016lx\n"
            "  r12=0x%016lx r13=0x%016lx r14=0x%016lx r15=0x%016lx\n"
            "  cr0=0x%016lx cr2=0x%016lx cr3=0x%016lx cr4=0x%016lx\n",
            regs->interrupt_num, regs->error_code, regs->cs, regs->rip,
            regs->rflags, regs->ss, regs->rsp, regs->rax, regs->rbx, regs->rcx,
            regs->rdx, regs->rbp, regs->rsi, regs->rdi, regs->r8, regs->r9,
            regs->r10, regs->r11, regs->r12, regs->r13, regs->r14, regs->r15,
            read_cr0(), read_cr2(), read_cr3(), read_cr4());
}

static void dump_stack_trace(uintptr_t ip, uintptr_t bp) {
    bool in_userland = ip < USER_VIRT_END;
    kprint("stack trace:\n");
    for (unsigned depth = 0;; ++depth) {
        if (depth >= 20) {
            kprint("  ...\n");
            break;
        }
        const struct symbol* symbol = in_userland ? NULL : ksyms_lookup(ip);
        if (symbol)
            kprintf("  0x%016lx %s+0x%lx\n", ip, symbol->name,
                    ip - symbol->addr);
        else
            kprintf("  0x%016lx\n", ip);

        if (safe_memcpy(&ip, (uintptr_t*)bp + 1, sizeof(uintptr_t)))
            break;
        if (safe_memcpy(&bp, (uintptr_t*)bp, sizeof(uintptr_t)))
            break;

        if (!ip || !bp)
            break;

        if (in_userland && ip >= KERNEL_VIRT_START) {
            // somehow stack looks like userland function is called from kernel
            break;
        }
        in_userland |= ip < USER_VIRT_END;
    }
}

noreturn void panic(const char* file, size_t line, const char* format, ...) {
    disable_interrupts();

    kprint("PANIC: ");
    va_list args;
    va_start(args, format);
    kvprintf(format, args);
    va_end(args);
    kprintf(" at %s:%zu\n", file, line);

    uintptr_t eip = read_eip();
    uintptr_t ebp = (uintptr_t)__builtin_frame_address(0);
    dump_stack_trace(eip, ebp);

    const char* mode = cmdline_lookup("panic");
    if (mode) {
        if (!strcmp(mode, "poweroff"))
            poweroff();
        int n = atoi(mode);
        if (n > 0) {
            kprintf("Rebooting in %d seconds..\n", n);
            delay(n * 1000000UL);
        }
        if (n != 0)
            reboot();
    }
    halt();
}

void dump_context(const struct registers* regs) {
    dump_registers(regs);
    dump_stack_trace(regs->rip, regs->rbp);
}

void handle_sysrq(char ch) {
    switch (ch) {
    case 'b':
        kprint("sysrq: Resetting\n");
        reboot();
        break;
    case 'c':
        kprint("sysrq: Trigger a crash\n");
        PANIC("sysrq triggered crash");
        break;
    case 's':
        kprint("sysrq: Emergency Sync\n");
        int rc = vfs_sync();
        (void)rc;
        kprint("Emergency Sync complete\n");
        break;
    }
}
