#include <kernel/api/x86/asm/processor-flags.h>
#include <kernel/arch/x86/memory/page_fault.h>
#include <kernel/arch/x86/task/context.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/vm.h>

bool x86_handle_page_fault(struct registers* regs, void* addr) {
    unsigned long error_code = regs->error_code;
    if (error_code & X86_PF_RSVD) {
        kprintf("Reserved bit violation at 0x%p\n", addr);
        return false;
    }

    unsigned flags = 0;
    if (error_code & X86_PF_PROT)
        flags |= PAGE_FAULT_PROT_VIOLATION;
    if (error_code & X86_PF_WRITE)
        flags |= PAGE_FAULT_WRITE;
    if (error_code & X86_PF_USER)
        flags |= PAGE_FAULT_USER;
    if (error_code & X86_PF_INSTR)
        flags |= PAGE_FAULT_INSTRUCTION;
    if (regs->flags & X86_EFLAGS_IF)
        flags |= PAGE_FAULT_INTERRUPTIBLE;
    if (vm_handle_page_fault(addr, flags))
        return true;

    if (safe_string_handle_page_fault(regs, error_code))
        return true;

    kprintf("Page fault (%s%s%s%s) at 0x%p\n",
            error_code & X86_PF_PROT ? "page-protection " : "non-present ",
            error_code & X86_PF_WRITE ? "write " : "read ",
            error_code & X86_PF_USER ? "user-mode " : "kernel-mode ",
            error_code & X86_PF_INSTR ? "instruction-fetch" : "data-access",
            addr);

    return false;
}
