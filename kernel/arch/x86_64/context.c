#include <common/string.h>
#include <kernel/arch/x86/cpu.h>
#include <kernel/arch/x86/msr.h>
#include <kernel/arch/x86/task/context.h>
#include <kernel/cpu.h>
#include <kernel/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/task/task.h>

static void restore_context(struct cpu* cpu, const struct arch_task* arch) {
    wrmsr(MSR_FS_BASE, arch->fs_base);
    // swapgs will load MSR_KERNEL_GS_BASE to the GS base
    wrmsr(MSR_KERNEL_GS_BASE, arch->gs_base);

    memcpy(cpu->arch.gdt + GDT_ENTRY_TLS_MIN, arch->tls, sizeof(arch->tls));

    // NOLINTBEGIN(bugprone-branch-clone)
    if (cpu_has_feature(cpu, X86_FEATURE_FXSR))
        __asm__ volatile("fxrstor %0" ::"m"(arch->fpu_state));
    else
        __asm__ volatile("frstor %0" ::"m"(arch->fpu_state));
    // NOLINTEND(bugprone-branch-clone)
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

    cpu->arch.tss.rsp0l = next->kernel_stack_top & 0xffffffff;
    cpu->arch.tss.rsp0h = next->kernel_stack_top >> 32;

    restore_context(cpu, &next->arch);

    // Call sched_reschedule(prev) only after switching to the stack of the next
    // task to prevent other CPUs from using the stack of the prev task while
    // we are still using it.
    __asm__ volatile(
        "pushq %%rbp\n"                    // rbp cannot be in the clobber list
        "movq $1f, %c[ip_offset](%%rdi)\n" // prev->arch.ip = $1f
        "movq %%rsp, %c[sp_offset](%%rdi)\n" // prev->arch.sp = rsp
        "movq %c[sp_offset](%%rbx), %%rsp\n" // rsp = next->arch.sp
        "call sched_reschedule\n"
        "movq %c[ip_offset](%%rbx), %%rbx\n" // rbx = next->arch.ip
        "jmp *%%rbx\n"
        "1:\n"
        "popq %%rbp\n"
        :
        : "D"(prev), "b"(next), [ip_offset] "i"(offsetof(struct task, arch.ip)),
          [sp_offset] "i"(offsetof(struct task, arch.sp))
        : "rax", "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11", "r12", "r13",
          "r14", "r15", "memory");
}

void arch_enter_user_mode(struct task* task, void* entry_point,
                          void* user_stack) {
    task->arch.fs_base = task->arch.gs_base = 0;
    memset(task->arch.tls, 0, sizeof(task->arch.tls));
    task->arch.fpu_state = initial_fpu_state;
    restore_context(cpu_get_current(), &task->arch);

    __asm__ volatile("pushq %%rax\n"
                     "pushq %%rbx\n"
                     "pushq %[eflags]\n"
                     "pushq %[user_cs]\n"
                     "pushq %%rcx\n"
                     "movq $0, %%rax\n"
                     "movq $0, %%rbx\n"
                     "movq $0, %%rcx\n"
                     "movq $0, %%rdx\n"
                     "movq $0, %%rsi\n"
                     "movq $0, %%rdi\n"
                     "movq $0, %%rbp\n"
                     "movq $0, %%r8\n"
                     "movq $0, %%r9\n"
                     "movq $0, %%r10\n"
                     "movq $0, %%r11\n"
                     "movq $0, %%r12\n"
                     "movq $0, %%r13\n"
                     "movq $0, %%r14\n"
                     "movq $0, %%r15\n"
                     "swapgs\n"
                     "iretq\n"
                     :
                     : [user_cs] "i"(USER_CS | 3),
                       [eflags] "i"(X86_EFLAGS_IF | X86_EFLAGS_FIXED),
                       "a"(USER_DS | 3), "b"(user_stack), "c"(entry_point));
    UNREACHABLE();
}

void arch_dump_registers(const struct registers* regs) {
    kprintf("interrupt_num=%lu error_code=0x%016lx\n"
            "   pc=0x%04lx:0x%016lx rflags=0x%016lx\n"
            "stack=0x%04lx:0x%016lx\n"
            "   ds=0x%04lx es=0x%04lx fs=0x%04lx gs=0x%04lx\n"
            "  rax=0x%016lx rbx=0x%016lx rcx=0x%016lx rdx=0x%016lx\n"
            "  rbp=0x%016lx rsi=0x%016lx rdi=0x%016lx\n"
            "   r8=0x%016lx  r9=0x%016lx r10=0x%016lx r11=0x%016lx\n"
            "  r12=0x%016lx r13=0x%016lx r14=0x%016lx r15=0x%016lx\n"
            "  cr0=0x%016lx cr2=0x%016lx cr3=0x%016lx cr4=0x%016lx\n",
            regs->interrupt_num, regs->error_code, regs->cs, regs->ip,
            regs->flags, regs->ss, regs->sp, regs->ds, regs->es, regs->fs,
            regs->gs, regs->ax, regs->bx, regs->cx, regs->dx, regs->bp,
            regs->si, regs->di, regs->r8, regs->r9, regs->r10, regs->r11,
            regs->r12, regs->r13, regs->r14, regs->r15, read_cr0(), read_cr2(),
            read_cr3(), read_cr4());
}
