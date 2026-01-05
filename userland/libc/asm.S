#include <sys/syscall.h>

    .text
    .global _start
_start:
    movq %rsp, %rdi // argc
    call __start // __start(&argc)
    ud2

// long syscall(long num, long, long, long, long, long, long);
    .global syscall
    .hidden syscall
    .type syscall, @function
syscall:
    pushq %rbx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %r11
    movq %rdi, %rax
    movq %rsi, %rbx
    movq %rdx, %r11
    movq %rcx, %rdx
    movq %r11, %rcx
    movq %r8, %rsi
    movq %r9, %rdi
    movq $0, %rbp
    int $SYSCALL_VECTOR
    popq %r11
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rbx
    ret

// In case of CLONE_VM, the child shares the same memory space with the parent,
// and fn and arg will be gone as soon as the parent returns from clone.
// Thus, we have to keep the fn and arg on the new stack so that the child can
// call fn(arg) after the clone.

// int __clone(int (*fn)(void*), void* stack, int flags, void* arg,
//             pid_t* parent_tid, void* tls, pid_t* child_tid);
    .globl __clone
    .hidden __clone
    .type __clone, @function
__clone:
    pushq %rbx
    pushq %rsi
    pushq %rdi
    movq 40(%rsp), %rcx   // rcx = new stack
    andq $-16, %rcx       // align the stack to 16 bytes boundary
    subq $16, %rcx         // reserve space for fn and arg
    movq 56(%rsp), %rax
    movq %rax, 8(%rcx)    // push arg to the new stack
    movq 16(%rsp), %rax
    movq %rax, (%rcx)     // push fn to the new stack
    movq 48(%rsp), %rbx   // rbx = flags
    movq 64(%rsp), %rdx   // rdx = parent_tid
    movq 80(%rsp), %rsi   // rsi = child_tid
    movq 72(%rsp), %rdi   // rdi = tls
    movq $SYS_clone, %rax
    int $SYSCALL_VECTOR   // clone(flags, stack, parent_tid, child_tid, tls)
    testq %rax, %rax
    jz child
    popq %rdi
    popq %rsi
    popq %rbx
    ret
child:
    popq %rax             // rax = fn
    call *%rax            // fn(arg)
    movq %rax, %rbx       // rbx = return value
    movq $SYS_exit, %rax
    int $SYSCALL_VECTOR   // exit(fn(arg))
    ud2

// long __syscall_return(long rc);
    .extern __syscall_return
    .hidden __syscall_return
    .type __syscall_return, @function

// pid_t vfork(void);
    .globl vfork
    .type vfork, @function
vfork:
    popq %rdx // save return address
    movq $SYS_vfork, %rax
    int $SYSCALL_VECTOR
    pushq %rdx
    pushq %rax
    call __syscall_return
    popq %rax
    ret

// void __sa_restorer(void);
    .globl __sa_restorer
    .hidden __sa_restorer
    .type __sa_restorer, @object
__sa_restorer:
    popq %rax // pop signum
    movl $SYS_sigreturn, %eax
    int $SYSCALL_VECTOR
    ud2
