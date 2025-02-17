#include "system.h"
#include "asm_wrapper.h"
#include "cpu.h"
#include "drivers/hid/ps2.h"
#include "kmsg.h"
#include "memory/memory.h"
#include "panic.h"
#include "safe_string.h"
#include <common/stdlib.h>
#include <common/string.h>
#include <stdarg.h>

static struct utsname utsname = {
    .sysname = "yagura",
    .nodename = "(none)",
    .release = "dev",
#ifdef YAGURA_VERSION
    .version = YAGURA_VERSION,
#else
    .version = "unknown",
#endif
    .machine = "i686",
    .domainname = "(none)",
};

static struct mutex utsname_lock;

void utsname_get(struct utsname* buf) {
    mutex_lock(&utsname_lock);
    *buf = utsname;
    mutex_unlock(&utsname_lock);
}

int utsname_set_hostname(const char* hostname, size_t len) {
    if (len >= sizeof(utsname.nodename))
        return -EINVAL;
    mutex_lock(&utsname_lock);
    strlcpy(utsname.nodename, hostname, len + 1);
    mutex_unlock(&utsname_lock);
    return 0;
}

int utsname_set_domainname(const char* domainname, size_t len) {
    if (len >= sizeof(utsname.domainname))
        return -EINVAL;
    mutex_lock(&utsname_lock);
    strlcpy(utsname.domainname, domainname, len + 1);
    mutex_unlock(&utsname_lock);
    return 0;
}

noreturn void reboot(void) {
    out8(PS2_COMMAND, 0xfe);
    halt();
}

noreturn void halt(void) {
    cli();
    if (smp_active) {
        struct ipi_message* msg = cpu_alloc_message();
        *msg = (struct ipi_message){
            .type = IPI_MESSAGE_HALT,
            .ref_count = num_cpus - 1,
        };
        cpu_broadcast_message(msg);
    }
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
    kprintf("interrupt_num=%u error_code=0x%08x\n"
            "   pc=0x%04x:0x%08x eflags=0x%08x\n"
            "stack=0x%04x:0x%08x\n"
            "   ds=0x%04x es=0x%04x fs=0x%04x gs=0x%04x\n"
            "  eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x\n"
            "  ebp=0x%08x esi=0x%08x edi=0x%08x\n"
            "  cr0=0x%08x cr2=0x%08x cr3=0x%08x cr4=0x%08x\n",
            regs->interrupt_num, regs->error_code, regs->cs, regs->eip,
            regs->eflags, regs->ss, regs->esp, regs->ds, regs->es, regs->fs,
            regs->gs, regs->eax, regs->ebx, regs->ecx, regs->edx, regs->ebp,
            regs->esi, regs->edi, read_cr0(), read_cr2(), read_cr3(),
            read_cr4());
}

static void dump_stack_trace(uintptr_t eip, uintptr_t ebp) {
    bool in_userland = eip < KERNEL_VIRT_ADDR;
    kprint("stack trace:\n");
    for (unsigned depth = 0;; ++depth) {
        if (depth >= 20) {
            kprint("  ...\n");
            break;
        }
        const struct symbol* symbol = in_userland ? NULL : ksyms_lookup(eip);
        if (symbol)
            kprintf("  0x%08x %s+0x%x\n", eip, symbol->name,
                    eip - symbol->addr);
        else
            kprintf("  0x%08x\n", eip);

        if (safe_memcpy(&eip, (uintptr_t*)ebp + 1, sizeof(uintptr_t)))
            break;
        if (safe_memcpy(&ebp, (uintptr_t*)ebp, sizeof(uintptr_t)))
            break;

        if (!eip || !ebp)
            break;

        if (in_userland && eip >= KERNEL_VIRT_ADDR) {
            // somehow stack looks like userland function is called from kernel
            break;
        }
        in_userland |= eip < KERNEL_VIRT_ADDR;
    }
}

noreturn void panic(const char* file, size_t line, const char* format, ...) {
    cli();

    kprint("PANIC: ");
    va_list args;
    va_start(args, format);
    kvprintf(format, args);
    va_end(args);
    kprintf(" at %s:%u\n", file, line);

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
            delay(n * 1000000);
        }
        if (n != 0)
            reboot();
    }
    halt();
}

void dump_context(const struct registers* regs) {
    dump_registers(regs);
    dump_stack_trace(regs->eip, regs->ebp);
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
    }
}
