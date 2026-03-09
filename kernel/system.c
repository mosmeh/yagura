#include <common/stdlib.h>
#include <common/string.h>
#include <kernel/arch/context.h>
#include <kernel/arch/io.h>
#include <kernel/arch/system.h>
#include <kernel/cpu.h>
#include <kernel/fs/vfs.h>
#include <kernel/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/system.h>
#include <kernel/task/task.h>

static char uts_nodename[SIZEOF_FIELD(struct utsname, nodename)] = "(none)";
static char uts_domainname[SIZEOF_FIELD(struct utsname, domainname)] = "(none)";
static struct mutex uts_lock;

void utsname_get(struct utsname* buf) {
    struct utsname utsname;
    if (cmdline_contains("uname_compat")) {
        utsname = (struct utsname){
            .sysname = "Linux",
            .release = "5.1.21",
            .version = "#1 SMP PREEMPT yagura " YAGURA_VERSION,
        };
    } else {
        utsname = (struct utsname){
            .sysname = "yagura",
            .release = "dev",
            .version = YAGURA_VERSION,
        };
    }
    strlcpy(utsname.machine, ARCH_UTS_MACHINE, sizeof(utsname.machine));
    {
        SCOPED_LOCK(mutex, &uts_lock);
        memcpy(utsname.nodename, uts_nodename, sizeof(uts_nodename));
        memcpy(utsname.domainname, uts_domainname, sizeof(uts_domainname));
    }
    *buf = utsname;
}

int utsname_set_hostname(const char* hostname, size_t len) {
    if (len >= sizeof(uts_nodename))
        return -EINVAL;
    SCOPED_LOCK(mutex, &uts_lock);
    memcpy(uts_nodename, hostname, len);
    memset(uts_nodename + len, 0, sizeof(uts_nodename) - len);
    return 0;
}

int utsname_set_domainname(const char* domainname, size_t len) {
    if (len >= sizeof(uts_domainname))
        return -EINVAL;
    SCOPED_LOCK(mutex, &uts_lock);
    memcpy(uts_domainname, domainname, len);
    memset(uts_domainname + len, 0, sizeof(uts_domainname) - len);
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

void panic(const char* format, ...) {
    arch_disable_interrupts();

    va_list args;
    va_start(args, format);
    kvprintf(format, args);
    va_end(args);

    kprint("stack trace:\n");
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

static void sysrq_reboot(void) { reboot(NULL); }

static void sysrq_crash(void) { PANIC("sysrq triggered crash"); }

static _Atomic(size_t) pending_syncs;

static void sync(struct work* work) {
    (void)work;
    for (;;) {
        ASSERT(pending_syncs > 0);

        int rc = vfs_sync();
        (void)rc;
        kprint("Emergency Sync complete\n");

        if (--pending_syncs == 0)
            break;
    }
}

static void sysrq_sync(void) {
    static struct work work;
    if (pending_syncs++ == 0)
        workqueue_submit(global_workqueue, &work, sync);
}

struct sysrq {
    const char* msg;
    void (*handler)(void);
};

static const struct sysrq sysrq_ops[] = {
    ['b'] = {"Resetting", sysrq_reboot},
    ['c'] = {"Trigger a crash", sysrq_crash},
    ['o'] = {"Power Off", poweroff},
    ['s'] = {"Emergency Sync", sysrq_sync},
};

void handle_sysrq(char ch) {
    if (ch < 0 || ARRAY_SIZE(sysrq_ops) <= (size_t)ch)
        return;
    const struct sysrq* op = &sysrq_ops[(size_t)ch];
    if (op->handler) {
        kprintf("sysrq: %s\n", op->msg);
        op->handler();
    }
}
