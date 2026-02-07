    .text

.macro swapgs_if_needed
    movq (8 * 22)(%rsp), %rax
    andq $3, %rax
    cmpq $0, %rax # if cs & 3 == 0
    je 1f
    swapgs
1:
.endm

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

    swapgs_if_needed

    cld
    movq %rsp, %rdi
    call isr_handler

// falls through

    .globl do_iret
do_iret:
    swapgs_if_needed

    addq $(8 * 4), %rsp # pop gs, fs, es, ds
    movq $0, %rax
    movw %ax, %es
    movw %ax, %ds
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
    addq $(8 * 2), %rsp # pop error_code and interrupt_num
    iretq
