#include "system.h"
#include "asm_wrapper.h"
#include "kprintf.h"
#include <stdbool.h>

noreturn void kpanic(const char* message, const char* file, size_t line) {
    kprintf("%s at %s:%u\n", message, file, line);
    cli();
    while (true)
        hlt();
}

void dump_registers(const registers* regs) {
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
