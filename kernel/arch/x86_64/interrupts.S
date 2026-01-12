    .text
    .globl isr_entry
isr_entry:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movw %ds, %ax
    pushq %rax
    movw %es, %ax
    pushq %rax
    pushq %fs
    pushq %gs

    movw $0, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    cld
    movq %rsp, %rdi
    call isr_handler

// falls through

    .globl do_iret
do_iret:
    popq %gs
    popq %fs
    popq %rax
    movq %rax, %es
    popq %rax
    movq %rax, %ds
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    addq $16, %rsp # pop error_code and interrupt_num
    iretq
