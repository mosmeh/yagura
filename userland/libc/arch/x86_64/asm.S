#include <sys/syscall.h>

    .text
    .global _start
_start:
    movq %rsp, %rdi // argc
    call __start // __start(&argc)
    ud2

// long __syscall(long num, long, long, long, long, long, long);
    .global __syscall
    .hidden __syscall
    .type __syscall, @function
__syscall:
    pushq %rbx
    pushq %rbp
    movq %rdi, %rax
    movq %rsi, %rbx
    movq %rdx, %r11
    movq %rcx, %rdx
    movq %r11, %rcx
    movq %r8, %rsi
    movq %r9, %rdi
    movq 0x18(%rsp), %rbp
    int $SYSCALL_VECTOR
    popq %rbp
    popq %rbx
    ret

// In case of CLONE_VM, the child shares the same memory space with the parent,
// and fn and arg will be gone as soon as the parent returns from clone.
// Thus, we have to keep the fn and arg on the new stack so that the child can
// call fn(arg) after the clone.

// int __clone_impl(int (*fn)(void*), void* stack, int flags, void* arg,
//                  pid_t* parent_tid, pid_t* child_tid, void* tls);
    .globl __clone_impl
    .hidden __clone_impl
    .type __clone_impl, @function
__clone_impl:
    pushq %rbx
    andq $-16, %rsi       // align the stack to 16 bytes boundary
    subq $16, %rsi        // reserve space for fn and arg
    movq %rcx, 8(%rsi)    // push arg to the new stack
    movq %rdi, (%rsi)     // push fn to the new stack
    movq %rsi, %rcx       // rcx = new stack
    movq %rdx, %rbx       // rbx = flags
    movq %r8, %rdx        // rdx = parent_tid
    movq 16(%rsp), %rsi   // rsi = tls
    movq %r9, %rdi        // rdi = child_tid
    movq $SYS_clone, %rax
    int $SYSCALL_VECTOR   // clone(flags, stack, parent_tid, tls, child_tid)
    testq %rax, %rax
    jz child
    popq %rbx
    ret
child:
    popq %rax             // rax = fn
    popq %rdi             // rdi = arg
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
    movq %rax, %rdi
    call __syscall_return
    ret

// void __sa_restorer(void);
    .globl __sa_restorer
    .hidden __sa_restorer
    .type __sa_restorer, @object
__sa_restorer:
    movl $SYS_rt_sigreturn, %eax
    int $SYSCALL_VECTOR
    ud2
