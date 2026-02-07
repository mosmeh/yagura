#include <common/string.h>
#include <kernel/api/x86/asm/processor-flags.h>
#include <kernel/arch/context.h>
#include <kernel/arch/x86/cpu.h>
#include <kernel/arch/x86/task/context.h>
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

int arch_clone_task(struct task* to, const struct task* from,
                    const struct registers* from_regs, void* user_stack) {
    to->arch = (struct arch_task){
        .ip = (uintptr_t)do_iret,
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
