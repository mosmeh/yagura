#include <common/string.h>
#include <kernel/api/x86/asm/prctl.h>
#include <kernel/api/x86/asm/processor-flags.h>
#include <kernel/arch/context.h>
#include <kernel/arch/x86/cpu.h>
#include <kernel/arch/x86/msr.h>
#include <kernel/arch/x86/syscall/syscall.h>
#include <kernel/arch/x86/task/context.h>
#include <kernel/interrupts.h>
#include <kernel/memory/safe_string.h>
#include <kernel/task/task.h>

void do_iret(struct registers);

int arch_init_task(struct task* task, void (*entry_point)(void)) {
    task->arch = (struct arch_task){
        .ip = (uintptr_t)do_iret,
        .fpu_state = initial_fpu_state,
    };

    task->arch.sp = task->kernel_stack_top - sizeof(struct registers);
    struct registers* regs = (struct registers*)task->arch.sp;
    *regs = (struct registers){
        .cs = KERNEL_CS,
        .ss = KERNEL_DS,
#ifdef ARCH_I386
        .ds = KERNEL_DS,
        .es = KERNEL_DS,
        .fs = CPU_SELECTOR,
        .gs = KERNEL_DS,
#endif
        .ip = (uintptr_t)entry_point,
        .sp = task->kernel_stack_top,
        .flags = X86_EFLAGS_IF | X86_EFLAGS_FIXED,
    };

    return 0;
}

int arch_clone_user_task(struct task* to, const struct task* from,
                         const struct registers* from_regs, void* user_stack) {
    to->arch = (struct arch_task){
        .ip = (uintptr_t)do_iret,
#ifdef ARCH_X86_64
        .fs_base = from->arch.fs_base,
        .gs_base = from->arch.gs_base,
#endif
        .fpu_state = from->arch.fpu_state,
    };
    memcpy(to->arch.tls, from->arch.tls, sizeof(to->arch.tls));

    to->arch.sp = to->kernel_stack_top - sizeof(struct registers);
    struct registers* to_regs = (struct registers*)to->arch.sp;
    *to_regs = *from_regs;
    to_regs->ax = 0; // return 0 in the child
    if (user_stack)
        to_regs->sp = (uintptr_t)user_stack;

    return 0;
}

void arch_walk_stack(uintptr_t bp, bool (*callback)(uintptr_t ip, void* data),
                     void* data) {
    for (;;) {
        uintptr_t ip;
        if (safe_memcpy(&ip, (uintptr_t*)bp + 1, sizeof(uintptr_t)))
            return;
        if (!ip)
            return;
        if (!callback(ip, data))
            return;
        if (safe_memcpy(&bp, (uintptr_t*)bp, sizeof(uintptr_t)))
            return;
        if (!bp)
            return;
    }
}

bool arch_is_user_mode(const struct registers* regs) {
    return (regs->cs & 3) == 3;
}

long sys_arch_prctl(int op, unsigned long addr) {
#ifdef ARCH_X86_64
    switch (op) {
    case ARCH_SET_FS: {
        if (!is_user_address((void*)addr))
            return -EPERM;
        SCOPED_DISABLE_INTERRUPTS();
        wrmsr(MSR_FS_BASE, addr);
        current->arch.fs_base = addr;
        return 0;
    }
    case ARCH_SET_GS: {
        if (!is_user_address((void*)addr))
            return -EPERM;
        SCOPED_DISABLE_INTERRUPTS();
        // swapgs will load MSR_KERNEL_GS_BASE to the GS base
        wrmsr(MSR_KERNEL_GS_BASE, addr);
        current->arch.gs_base = addr;
        return 0;
    }
    case ARCH_GET_FS:
        if (copy_to_user((void*)addr, &current->arch.fs_base,
                         sizeof(uintptr_t)))
            return -EFAULT;
        return 0;
    case ARCH_GET_GS:
        if (copy_to_user((void*)addr, &current->arch.gs_base,
                         sizeof(uintptr_t)))
            return -EFAULT;
        return 0;
    }
#else
    (void)op;
    (void)addr;
#endif
    return -EINVAL;
}
