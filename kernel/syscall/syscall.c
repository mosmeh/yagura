#include <common/stdio.h>
#include <common/string.h>
#include <kernel/api/errno.h>
#include <kernel/api/sys/syscall.h>
#include <kernel/arch/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/syscall/syscall.h>
#include <kernel/system.h>
#include <kernel/task/signal.h>

SYSCALL0(ni_syscall) { return -ENOSYS; }

enum log_level {
    LOG_UNINITIALIZED,
    LOG_NONE,
    LOG_ALL,
    LOG_IMPLEMENTED,
    LOG_UNIMPLEMENTED,
};

static enum log_level get_log_level(void) {
    static const char* const cmdline_key = "syscall_log";
    static _Atomic(enum log_level) cached_level = LOG_UNINITIALIZED;

    if (cached_level != LOG_UNINITIALIZED)
        return cached_level;

    if (!cmdline_contains(cmdline_key)) {
        cached_level = LOG_NONE;
        return cached_level;
    }

    const char* level = cmdline_lookup(cmdline_key);
    if (!level || level[0] == '\0' || !strcmp(level, "all"))
        cached_level = LOG_ALL;
    else if (!strcmp(level, "implemented"))
        cached_level = LOG_IMPLEMENTED;
    else if (!strcmp(level, "unimplemented"))
        cached_level = LOG_UNIMPLEMENTED;
    else
        cached_level = LOG_NONE;
    return cached_level;
}

NODISCARD static long dispatch(const struct syscall_abi* abi,
                               struct registers* regs) {
    unsigned long number;
    unsigned long args[6];
    abi->decode(regs, &number, args);

    const struct syscall* syscall =
        number < abi->table_len ? &abi->table[number] : NULL;

    syscall_fn handler = syscall ? syscall->handler : NULL;
    if (!handler)
        handler = sys_ni_syscall;
    bool is_implemented = handler != sys_ni_syscall;

    switch (get_log_level()) {
    case LOG_NONE:
        return handler(regs, args);
    case LOG_ALL:
        break;
    case LOG_IMPLEMENTED:
        if (!is_implemented)
            return handler(regs, args);
        break;
    case LOG_UNIMPLEMENTED:
        if (is_implemented)
            return handler(regs, args);
        break;
    default:
        UNREACHABLE();
    }

    const char* name = syscall ? syscall->name : NULL;
    char name_buf[32];
    if (!name) {
        ASSERT((size_t)snprintf(name_buf, sizeof(name_buf), "<%lu>", number) <
               sizeof(name_buf));
        name = name_buf;
    }
    kprintf("syscall: %s(%#lx, %#lx, %#lx, %#lx, %#lx, %#lx)%s\n", name,
            args[0], args[1], args[2], args[3], args[4], args[5],
            is_implemented ? "" : " (unimplemented)");

    return handler(regs, args);
}

void syscall_handle(const struct syscall_abi* abi, struct registers* regs) {
    ASSERT(arch_interrupts_enabled());

    long ret = dispatch(abi, regs);

    struct sigaction act;
    int signum = ASSERT_OK(signal_pop(&act));

    switch (ret) {
    case -ERESTARTSYS:
        // Restart the syscall when
        // - There is no signal handler to run, or
        // - The signal handler has the SA_RESTART flag set
        if (!signum || (act.sa_flags & SA_RESTART))
            abi->restart(regs);
        else
            abi->set_return_value(regs, -EINTR);
        break;
    case -ERAWRETURN:
        break;
    default:
        if (IS_ERR(ret)) {
            // Ensure we don't return kernel internal errors to userland
            ASSERT(ret >= -EMAXERRNO);
        }
        abi->set_return_value(regs, ret);
        break;
    }

    if (signum)
        signal_handle(regs, signum, &act);
}
