#include <common/stdlib.h>
#include <common/string.h>
#include <kernel/arch/context.h>
#include <kernel/arch/io.h>
#include <kernel/arch/system.h>
#include <kernel/cpu.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/system.h>

static struct utsname utsname = {
    .sysname = "yagura",
    .nodename = "(none)",
    .release = "dev",
    .version = YAGURA_VERSION,
    .machine = ARCH_UTS_MACHINE,
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
    memcpy(utsname.nodename, hostname, len);
    memset(utsname.nodename + len, 0, sizeof(utsname.nodename) - len);
    return 0;
}

int utsname_set_domainname(const char* domainname, size_t len) {
    if (len >= sizeof(utsname.domainname))
        return -EINVAL;
    SCOPED_LOCK(mutex, &utsname_lock);
    memcpy(utsname.domainname, domainname, len);
    memset(utsname.domainname + len, 0, sizeof(utsname.domainname) - len);
    return 0;
}

void reboot(const char* cmd) {
    arch_disable_interrupts();
    if (cmd)
        kprintf("Restarting system with command '%s'\n", cmd);
    else
        kprint("Restarting system\n");
    arch_reboot();
    halt();
}

void poweroff(void) {
    arch_disable_interrupts();
    kprint("Power down\n");
    arch_poweroff();
    halt();
}

void halt(void) {
    arch_disable_interrupts();
    kprint("System halted\n");
    if (arch_smp_active())
        cpu_broadcast_message_coalesced(IPI_MESSAGE_HALT, true);
    arch_cpu_halt();
}

struct stack_walk {
    int depth;
    bool in_userland;
};

static bool print_stack_frame(uintptr_t ip, void* data) {
    struct stack_walk* walk = data;
    if (!ip)
        return false;
    if (walk->depth >= 20) {
        kprint("  ...\n");
        return false;
    }
    const struct symbol* symbol =
        is_kernel_address((void*)ip) ? ksyms_lookup(ip) : NULL;
    if (symbol)
        kprintf("  0x%p %s+0x%lx\n", (void*)ip, symbol->name,
                (unsigned long)(ip - symbol->addr));
    else
        kprintf("  0x%p\n", (void*)ip);
    if (walk->in_userland && is_kernel_address((void*)ip)) {
        // Stack trace says a userland function was called from kernel land,
        // which should not happen. The stack trace is probably corrupted.
        return false;
    }
    walk->in_userland |= is_user_address((void*)ip);
    ++walk->depth;
    return true;
}

void dump_stack_trace(uintptr_t ip, uintptr_t bp) {
    kprint("stack trace:\n");
    struct stack_walk walk = {0};
    if (!print_stack_frame(ip, &walk))
        return;
    arch_walk_stack(bp, print_stack_frame, &walk);
}

void panic(const char* file, size_t line, const char* format, ...) {
    arch_disable_interrupts();

    kprint("PANIC: ");
    va_list args;
    va_start(args, format);
    kvprintf(format, args);
    va_end(args);
    kprintf(" at %s:%zu\n"
            "stack trace:\n",
            file, line);
    struct stack_walk walk = {0};
    uintptr_t bp = (uintptr_t)__builtin_frame_address(0);
    arch_walk_stack(bp, print_stack_frame, &walk);

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
            reboot(NULL);
    }
    halt();
}

void handle_sysrq(char ch) {
    switch (ch) {
    case 'b':
        kprint("sysrq: Resetting\n");
        reboot(NULL);
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
