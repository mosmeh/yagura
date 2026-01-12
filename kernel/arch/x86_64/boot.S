#include <kernel/api/x86/asm/processor-flags.h>
#include <kernel/arch/x86/memory/page_table.h>
#include <kernel/arch/x86/msr.h>
#include <kernel/arch/x86/smp.h>
#include <kernel/memory/memory.h>
#include <kernel/system.h>

    .section .init_text, "ax", @progbits
    .globl _start
_start:
    .code32
    cli
    cld

    # Virtual address    Physical address      Size Description
    # 0x0000000000000000 0x0000000000000000   4 MiB identity mapping
    # 0xffffffffc0000000 0x0000000000000000   4 MiB higher half kernel
    # 0xffffffffc0400000 (no PTE present)     4 MiB kmap

    # Page table (mapping first 4 MiB of physical memory)
    movl $(PTE_PRESENT | PTE_WRITE | PTE_GLOBAL), %esi
    movl $pt_kernel_image, %edi
    movl $1024, %ecx
1:
    movl %esi, (%edi)
    addl $PAGE_SIZE, %esi
    addl $8, %edi
    loop 1b

    # Save parameters from Multiboot
    movl %eax, %edi
    movl %ebx, %esi

    # PDE (mapping 1st 2 MiB of physical memory)
    movl $pt_kernel_image, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pd_identity
    movl %eax, pd_high

    # PDE (mapping 2nd 2 MiB of physical memory)
    movl $pt_kernel_image2, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pd_identity + 8
    movl %eax, pd_high + 8

    # PDE (mapping 1st 2 MiB of kmap)
    movl $pt_kmap, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pd_high + 2 * 8

    # PDE (mapping 2nd 2 MiB of kmap)
    movl $pt_kmap2, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pd_high + 3 * 8

    # PDPTE (identity mapping)
    movl $pd_identity, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pdpt_identity

    # PDPTE (higher half)
    movl $pd_high, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pdpt_high + 511 * 8

    # PML4TE (identity mapping)
    movl $pdpt_identity, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pml4t

    # PML4TE (higher half)
    movl $pdpt_high, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pml4t + 511 * 8

    movl $pml4t, %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl $(X86_CR4_PAE | X86_CR4_PSE), %eax
    movl %eax, %cr4

    movl $MSR_EFER, %ecx
    rdmsr
    orl $EFER_LME, %eax
    wrmsr

    movl %cr0, %eax
    orl $(X86_CR0_PG | X86_CR0_WP | X86_CR0_PE), %eax
    movl %eax, %cr0

    movl $gdtr64, %eax
    lgdt (%eax)
    ljmpl $8, $long_mode

    .code64
long_mode:
    mov $0, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    jmp higher_half_start

ap_long_mode:
    mov $0, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    # ebx = atomic_fetch_add(&ap_id, 1)
    movl $1, %ebx
    lock; xaddl %ebx, ap_id

    .extern ap_stack_top
    # rsp = ap_stack_top - STACK_SIZE * rbx
    movq $STACK_SIZE, %rax
    mulq %rbx
    movq ap_stack_top, %rsp
    subq %rax, %rsp

    .extern ap_start
    .type ap_start, @function
    call ap_start

    cli
1:
    hlt
    jmp 1b

    .section .init_rodata, "a", @progbits
gdt64:
    .quad 0
    .quad (1<<43) | (1<<44) | (1<<47) | (1<<53) // executable, code segment, present, 64-bit
gdtr64:
    .short . - gdt64 - 1
    .quad gdt64

    .section .init_bss, "aw", @nobits
    .align PAGE_SIZE
    .globl kernel_pml_top_start
kernel_pml_top_start:
pml4t:
    .skip PAGE_SIZE

pd_identity:
    .skip PAGE_SIZE
pd_high:
    .skip PAGE_SIZE

pdpt_identity:
    .skip PAGE_SIZE
pdpt_high:
    .skip PAGE_SIZE

pt_kernel_image:
    .skip PAGE_SIZE
pt_kernel_image2:
    .skip PAGE_SIZE
    .globl kmap_page_table_start
kmap_page_table_start:
pt_kmap:
    .skip PAGE_SIZE
pt_kmap2:
    .skip PAGE_SIZE

ap_id:
    .long 0

    .text
    .code64
higher_half_start:
    # remove identity mapping
    movq $0, pml4t + KERNEL_IMAGE_START
    movq $0, pdpt_identity + KERNEL_IMAGE_START
    movq $pml4t, %rax
    movq %rax, %cr3

    mov $initial_kernel_stack_top, %rsp
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
    movl $pml4t, %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl $(X86_CR4_PAE | X86_CR4_PSE), %eax
    movl %eax, %cr4

    movl $MSR_EFER, %ecx
    rdmsr
    orl $EFER_LME, %eax
    wrmsr

    movl %cr0, %eax
    orl $(X86_CR0_PG | X86_CR0_WP), %eax
    movl %eax, %cr0

    movl $gdtr64, %eax
    lgdt (%eax)
    ljmpl $8, $ap_long_mode
ap_trampoline_end:

    .bss
    .globl initial_kernel_stack_base, initial_kernel_stack_top
    .align PAGE_SIZE
initial_kernel_stack_base:
    .skip STACK_SIZE
initial_kernel_stack_top:
