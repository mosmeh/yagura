#include "private.h"
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/system.h>

void memory_init(const multiboot_info_t* mb_info) {
    vm_init();
    vm_region_init();
    page_init(mb_info);
    vm_obj_init();
}

bool memory_handle_page_fault(struct registers* regs, void* virt_addr) {
    uint32_t error_code = regs->error_code;
    ASSERT(!(error_code & X86_PF_RSVD));

    if (vm_handle_page_fault(virt_addr, error_code))
        return true;
    if (safe_string_handle_page_fault(regs))
        return true;

    kprintf("Page fault (%s%s%s%s) at %p\n",
            error_code & X86_PF_PROT ? "page-protection " : "non-present ",
            error_code & X86_PF_WRITE ? "write " : "read ",
            error_code & X86_PF_USER ? "user-mode " : "kernel-mode ",
            error_code & X86_PF_INSTR ? "instruction-fetch" : "data-access",
            virt_addr);
    return false;
}
