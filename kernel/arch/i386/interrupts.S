#include <kernel/arch/x86/gdt.h>

    .text
    .globl isr_entry
isr_entry:
    pushl %eax
    pushl %ebx
    pushl %ecx
    pushl %edx
    pushl %esi
    pushl %edi
    pushl %ebp
    pushl %ds
    pushl %es
    pushl %fs
    pushl %gs

    movw $KERNEL_DS, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %gs
    movw $CPU_SELECTOR, %ax
    movw %ax, %fs

    cld

    movl %esp, %eax
    pushl %eax

    call isr_handler

    addl $4, %esp # pop esp

// falls through

    .globl do_iret
do_iret:
    popl %gs
    popl %fs
    popl %es
    popl %ds
    popl %ebp
    popl %edi
    popl %esi
    popl %edx
    popl %ecx
    popl %ebx
    popl %eax

    addl $(4 * 2), %esp # pop error_code and interrupt_num
    iret
