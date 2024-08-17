#define ASM_FILE
#include <kernel/gdt.h>

    .text
    .globl isr_entry
isr_entry:
    pusha
    pushl %ds
    pushl %es
    pushl %fs
    pushl %gs
    pushl %ss

    movw $KERNEL_DS, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    movl %esp, %eax
    pushl %eax

    call isr_handler

    addl $4, %esp # pop esp

// falls through

    .globl do_iret
do_iret:
    addl $4, %esp # pop ss
    popl %gs
    popl %fs
    popl %es
    popl %ds
    popa

    addl $8, %esp # pop err_code and num
    iret
