#include <common/string.h>
#include <kernel/arch/x86/cpu.h>
#include <kernel/arch/x86/task/context.h>
#include <kernel/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/safe_string.h>
#include <kernel/task/task.h>

void __reschedule(struct arch_task* task) {
    sched_reschedule(CONTAINER_OF(task, struct task, arch));
}

void arch_switch_context(struct task* prev, struct task* next) {
    ASSERT(!arch_interrupts_enabled());

    struct cpu* cpu = cpu_get_current();

    // NOLINTBEGIN(bugprone-branch-clone)
    if (cpu_has_feature(cpu, X86_FEATURE_FXSR))
        __asm__ volatile("fxsave %0" : "=m"(prev->arch.fpu_state));
    else
        __asm__ volatile("fnsave %0" : "=m"(prev->arch.fpu_state));
    // NOLINTEND(bugprone-branch-clone)

    cpu->arch.tss.esp0 = next->kernel_stack_top;
    memcpy(cpu->arch.gdt + GDT_ENTRY_TLS_MIN, next->arch.tls,
           sizeof(next->arch.tls));

    // NOLINTBEGIN(bugprone-branch-clone)
    if (cpu_has_feature(cpu, X86_FEATURE_FXSR))
        __asm__ volatile("fxrstor %0" ::"m"(next->arch.fpu_state));
    else
        __asm__ volatile("frstor %0" ::"m"(next->arch.fpu_state));
    // NOLINTEND(bugprone-branch-clone)

    // Call __reschedule(prev) after switching to the stack of the next
    // task to prevent other CPUs from using the stack of prev_task while
    // we are still using it.
    __asm__ volatile("pushl %%ebp\n"       // ebp cannot be in the clobber list
                     "movl $1f, (%%eax)\n" // prev->ip = $1f
                     "movl %%esp, 0x04(%%eax)\n" // prev->sp = esp
                     "movl 0x04(%%ebx), %%esp\n" // esp = next->sp
                     "pushl %%eax\n"
                     "call __reschedule\n"
                     "add $4, %%esp\n"
                     "movl (%%ebx), %%eax\n" // eax = next->ip
                     "jmp *%%eax\n"
                     "1:\n"
                     "popl %%ebp\n"
                     :
                     : "a"(&prev->arch), "b"(&next->arch)
                     : "ecx", "edx", "esi", "edi", "memory");
}

void arch_enter_user_mode(struct task* task, void* entry_point,
                          void* user_stack) {
    memset(task->arch.tls, 0, sizeof(task->arch.tls));

    __asm__ volatile("movw %%ax, %%ds\n"
                     "movw %%ax, %%es\n"
                     "movw %%ax, %%fs\n"
                     "movw %%ax, %%gs\n"
                     "pushl %%eax\n"
                     "pushl %%ebx\n"
                     "pushl %[eflags]\n"
                     "pushl %[user_cs]\n"
                     "pushl %%ecx\n"
                     "movl $0, %%eax\n"
                     "movl $0, %%ebx\n"
                     "movl $0, %%ecx\n"
                     "movl $0, %%edx\n"
                     "movl $0, %%esi\n"
                     "movl $0, %%edi\n"
                     "movl $0, %%ebp\n"
                     "iret\n"
                     :
                     : [user_cs] "i"(USER_CS | 3),
                       [eflags] "i"(X86_EFLAGS_IF | X86_EFLAGS_FIXED),
                       "a"(USER_DS | 3), "b"(user_stack), "c"(entry_point));
    UNREACHABLE();
}

void arch_dump_registers(const struct registers* regs) {
    kprintf("interrupt_num=%lu error_code=0x%08lx\n"
            "   pc=0x%04lx:0x%08lx eflags=0x%08lx\n"
            "stack=0x%04lx:0x%08lx\n"
            "   ds=0x%04lx es=0x%04lx fs=0x%04lx gs=0x%04lx\n"
            "  eax=0x%08lx ebx=0x%08lx ecx=0x%08lx edx=0x%08lx\n"
            "  ebp=0x%08lx esi=0x%08lx edi=0x%08lx\n"
            "  cr0=0x%08lx cr2=0x%08lx cr3=0x%08lx cr4=0x%08lx\n",
            regs->interrupt_num, regs->error_code, regs->cs, regs->ip,
            regs->flags, regs->ss, regs->sp, regs->ds, regs->es, regs->fs,
            regs->gs, regs->ax, regs->bx, regs->cx, regs->dx, regs->bp,
            regs->si, regs->di, read_cr0(), read_cr2(), read_cr3(), read_cr4());
}
