#include "system.h"
#include "asm_wrapper.h"
#include "boot_defs.h"
#include "drivers/hid/hid.h"
#include "kprintf.h"
#include "panic.h"
#include "safe_string.h"
#include <common/stdlib.h>
#include <stdarg.h>
#include <string.h>

static struct utsname uts = {
    .sysname = "yagura",
    .nodename = "localhost",
    .release = "dev",
#ifdef YAGURA_VERSION
    .version = YAGURA_VERSION,
#else
    .version = "unknown",
#endif
    .machine = "i686",
};

const struct utsname* utsname(void) { return &uts; }

noreturn void reboot(void) {
    out8(PS2_COMMAND, 0xfe);
    halt();
}

noreturn void halt(void) {
    cli();
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

static void dump_registers(const registers* regs) {
    uint16_t ss;
    uint32_t esp;
    if (regs->cs & 3) {
        ss = regs->user_ss;
        esp = regs->user_esp;
    } else {
        ss = regs->ss;
        esp = regs->esp;
    }
    kprintf("  num=%u err_code=0x%08x\n"
            "   pc=0x%04x:0x%08x eflags=0x%08x\n"
            "stack=0x%04x:0x%08x\n"
            "   ds=0x%04x es=0x%04x fs=0x%04x gs=0x%04x\n"
            "  eax=0x%08x ebx=0x%08x ecx=0x%08x edx=0x%08x\n"
            "  ebp=0x%08x esp=0x%08x esi=0x%08x edi=0x%08x\n"
            "  cr0=0x%08x cr2=0x%08x cr3=0x%08x cr4=0x%08x\n",
            regs->num, regs->err_code, regs->cs, regs->eip, regs->eflags, ss,
            esp, regs->ds, regs->es, regs->fs, regs->gs, regs->eax, regs->ebx,
            regs->ecx, regs->edx, regs->ebp, regs->esp, regs->esi, regs->edi,
            read_cr0(), read_cr2(), read_cr3(), read_cr4());
}

static void dump_stack_trace(uintptr_t eip, uintptr_t ebp) {
    bool in_userland = eip < KERNEL_VIRT_ADDR;
    kputs("stack trace:\n");
    for (unsigned depth = 0;; ++depth) {
        if (depth >= 20) {
            kputs("  ...\n");
            break;
        }
        const struct symbol* symbol = in_userland ? NULL : ksyms_lookup(eip);
        if (symbol)
            kprintf("  0x%08x %s+0x%x\n", eip, symbol->name,
                    eip - symbol->addr);
        else
            kprintf("  0x%08x\n", eip);

        if (!safe_memcpy(&eip, (uintptr_t*)ebp + 1, sizeof(uintptr_t)))
            break;
        if (!safe_memcpy(&ebp, (uintptr_t*)ebp, sizeof(uintptr_t)))
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

    kputs("PANIC: ");
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

void dump_context(const registers* regs) {
    dump_registers(regs);
    dump_stack_trace(regs->eip, regs->ebp);
}

void handle_sysrq(char ch) {
    switch (ch) {
    case 'b':
        kputs("sysrq: Resetting\n");
        reboot();
        break;
    case 'c':
        kputs("sysrq: Trigger a crash\n");
        PANIC("sysrq triggered crash");
        break;
    }
}
