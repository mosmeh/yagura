#define ASM_FILE
#include <kernel/api/sys/syscall.h>

#define SYS_clone 5
#define SYS_exit 11

// In case of CLONE_VM, the child shares the same memory space with the parent,
// and fn and arg will be gone as soon as the parent returns from clone.
// Thus, we have to keep the fn and arg on the new stack so that the child can
// call fn(arg) after the clone.

    .text
// int __clone(int (*fn)(void*), void* stack, int flags, void* arg);
    .hidden __clone
    .type   __clone, @function
    .globl __clone
__clone:
    movl 8(%esp), %ecx    // ecx = new stack
    andl $-16, %ecx       // align the stack to 16 bytes boundary
    subl $8, %ecx         // reserve space for fn and arg
    movl 16(%esp), %eax
    movl %eax, 4(%ecx)    // push arg to the new stack
    movl 4(%esp), %eax
    movl %eax, (%ecx)     // push fn to the new stack
    movl 12(%esp), %edx   // edx = flags
    movl $SYS_clone, %eax
    int $SYSCALL_VECTOR   // clone(flags, stack)
    testl %eax, %eax
    jz child
    ret
child:
    popl %eax             // eax = fn
    call *%eax            // fn(arg)
    movl %eax, %edx       // edx = return value
    movl $SYS_exit, %eax
    int $SYSCALL_VECTOR   // exit(fn(arg))
    ud2
