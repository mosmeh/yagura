#include <sys/syscall.h>

    .text
// int syscall(int num, int, int, int, int, int, int);
    .global syscall
    .hidden syscall
    .type syscall, @function
syscall:
    pushl %ebx
    pushl %esi
    pushl %edi
    pushl %ebp
    movl 20(%esp), %eax
    movl 24(%esp), %ebx
    movl 28(%esp), %ecx
    movl 32(%esp), %edx
    movl 36(%esp), %esi
    movl 40(%esp), %edi
    movl 44(%esp), %ebp
    int $SYSCALL_VECTOR
    popl %ebp
    popl %edi
    popl %esi
    popl %ebx
    ret

// In case of CLONE_VM, the child shares the same memory space with the parent,
// and fn and arg will be gone as soon as the parent returns from clone.
// Thus, we have to keep the fn and arg on the new stack so that the child can
// call fn(arg) after the clone.

// int __clone(int (*fn)(void*), void* stack, int flags, void* arg);
    .globl __clone
    .hidden __clone
    .type __clone, @function
__clone:
    pushl %ebx
    movl 12(%esp), %ecx   // ecx = new stack
    andl $-16, %ecx       // align the stack to 16 bytes boundary
    subl $8, %ecx         // reserve space for fn and arg
    movl 20(%esp), %eax
    movl %eax, 4(%ecx)    // push arg to the new stack
    movl 8(%esp), %eax
    movl %eax, (%ecx)     // push fn to the new stack
    movl 16(%esp), %ebx   // ebx = flags
    movl $SYS_clone, %eax
    int $SYSCALL_VECTOR   // clone(flags, stack)
    testl %eax, %eax
    jz child
    popl %ebx
    ret
child:
    popl %eax             // eax = fn
    call *%eax            // fn(arg)
    movl %eax, %ebx       // ebx = return value
    movl $SYS_exit, %eax
    int $SYSCALL_VECTOR   // exit(fn(arg))
    ud2
