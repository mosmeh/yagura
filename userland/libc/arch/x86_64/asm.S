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
    movq %rdi, %rax   // syscall number
    movq %rsi, %rdi   // arg1
    movq %rdx, %rsi   // arg2
    movq %rcx, %rdx   // arg3
    movq %r8, %r10    // arg4
    movq %r9, %r8     // arg5
    movq 8(%rsp), %r9 // arg6
    syscall
    ret

// In case of CLONE_VM, the child shares the same memory space with the parent,
// and fn and arg will be gone as soon as the parent returns from clone.
// Thus, we have to keep the fn and arg on the new stack so that the child can
// call fn(arg) after the clone.

// int __clone(int (*fn)(void*), void* stack, int flags, void* arg,
//             pid_t* parent_tid, pid_t* child_tid, void* tls);
    .globl __clone
    .hidden __clone
    .type __clone, @function
__clone:
    andq $-16, %rsi       // align the stack to 16 bytes boundary
    subq $16, %rsi        // reserve space for fn and arg
    movq %rcx, 8(%rsi)    // push arg to the new stack
    movq %rdi, (%rsi)     // push fn to the new stack
    movq %rdx, %rdi       // rdi = flags
    movq %r8, %rdx        // rdx = parent_tid
    movq %r9, %r10        // r10 = child_tid
    movq 8(%rsp), %r8     // r8 = tls
    movq $SYS_clone, %rax
    syscall               // clone(flags, stack, parent_tid, child_tid, tls)
    testq %rax, %rax
    jz child
    ret
child:
    popq %rax             // rax = fn
    popq %rdi             // rdi = arg
    call *%rax            // fn(arg)
    movq %rax, %rdi       // rdi = return value
    movq $SYS_exit, %rax
    syscall               // exit(fn(arg))
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
    syscall
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
    syscall
    ud2

// pthread_t pthread_self(void);
    .globl pthread_self
    .type pthread_self, @function
pthread_self:
    movq %fs:0, %rax
    ret
