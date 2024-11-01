#define ASM_FILE
#include <kernel/gdt.h>

    .text
    .globl isr_entry
isr_entry:
    pushl %eax
    pushl %ebx
    pushl %ecx
    pushl %edx
    pushl %ebp
    pushl %esi
    pushl %edi
    pushl %ds
    pushl %es
    pushl %fs
    pushl %gs

    movw $KERNEL_DS, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

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
    popl %edi
    popl %esi
    popl %ebp
    popl %edx
    popl %ecx
    popl %ebx
    popl %eax

    addl $8, %esp # pop error_code and interrupt_num
    iret
