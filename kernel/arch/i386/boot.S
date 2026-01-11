#include <kernel/api/x86/asm/processor-flags.h>
#include <kernel/arch/x86/memory/page_table.h>
#include <kernel/arch/x86/smp.h>
#include <kernel/memory/memory.h>
#include <kernel/system.h>

#define PD_SHIFT 22

    .section .init_text, "ax", @progbits
    .globl _start
_start:
    cli
    cld

    # page table mapping first 4 MiB of physical memory
    movl $(PTE_PRESENT | PTE_WRITE | PTE_GLOBAL), %esi
    movl $pt_kernel_image, %edi
    movl $1024, %ecx
1:
    movl %esi, (%edi)
    addl $PAGE_SIZE, %esi
    addl $4, %edi
    loop 1b

    movl $pt_kernel_image, %edx
    orl $(PTE_PRESENT | PTE_WRITE), %edx

    # identity mapping
    movl %edx, pd

    # higher half mapping
    movl %edx, pd + (KERNEL_IMAGE_START >> PD_SHIFT) * 4

    movl $pt_kmap, %edx
    orl $(PTE_PRESENT | PTE_WRITE), %edx
    movl %edx, pd + (KMAP_START >> PD_SHIFT) * 4

    movl $pd, %edx
    movl %edx, %cr3

    movl %cr0, %edx
    orl $(X86_CR0_PG | X86_CR0_WP), %edx
    movl %edx, %cr0

    lea paging_enabled, %edx
    jmp *%edx

    .section .init_bss, "aw", @nobits
    .align PAGE_SIZE
    .globl kernel_pml_top_start
kernel_pml_top_start:
pd:
    .skip PAGE_SIZE
    .align PAGE_SIZE
pt_kernel_image:
    .skip PAGE_SIZE
    .globl kmap_page_table_start
kmap_page_table_start:
pt_kmap:
    .skip PAGE_SIZE

    .text
paging_enabled:
    # remove identity mapping
    movl $0, pd + KERNEL_IMAGE_START
    movl $pd, %edx
    movl %edx, %cr3

    movl $initial_kernel_stack_top, %esp
    pushl %ebx # Multiboot info struct
    pushl %eax # Multiboot magic

    call start

    cli
1:
    hlt
    jmp 1b

    .code16
    .globl ap_trampoline_start, ap_trampoline_end
    .align PAGE_SIZE
ap_trampoline_start:
    cli
    cld

    xorw %ax, %ax
    movw %ax, %ds

    lgdtl ap_initial_gdtr - ap_trampoline_start + AP_TRAMPOLINE_ADDR

    movl %cr0, %eax
    orl $X86_CR0_PE, %eax
    movl %eax, %cr0

    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    ljmp $8, $(ap_trampoline_start32 - ap_trampoline_start + AP_TRAMPOLINE_ADDR)

ap_initial_gdt:
    .long 0, 0
    .long 0x0000ffff, 0x00cf9a00 # code
    .long 0x0000ffff, 0x00cf9200 # data
ap_initial_gdtr:
    .word ap_initial_gdtr - ap_initial_gdt - 1
    .long ap_initial_gdt - ap_trampoline_start + AP_TRAMPOLINE_ADDR

    .code32
ap_trampoline_start32:
    movl $pd, %eax
    movl %eax, %cr3

    movl %cr0, %eax
    orl $(X86_CR0_PG | X86_CR0_WP), %eax
    movl %eax, %cr0

    # ebx = atomic_fetch_add(&ap_id, 1)
    movl $1, %ebx
    lock; xaddl %ebx, (ap_id - ap_trampoline_start + AP_TRAMPOLINE_ADDR)

    .extern ap_stack_top
    # esp = ap_stack_top - STACK_SIZE * ebx
    movl $STACK_SIZE, %eax
    mull %ebx
    movl ap_stack_top, %esp
    subl %eax, %esp

    .extern ap_start
    .type ap_start, @function
    ljmp $8, $ap_start
ap_trampoline_end:

    .bss
    .globl initial_kernel_stack_base, initial_kernel_stack_top
    .align PAGE_SIZE
initial_kernel_stack_base:
    .skip STACK_SIZE
initial_kernel_stack_top:

ap_id:
    .long 0
