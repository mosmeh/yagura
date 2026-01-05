#define ASM_FILE
#include <kernel/multiboot.h>
#include <kernel/api/asm/processor-flags.h>
#include <kernel/system.h>
#include <kernel/memory/memory.h>

#define FLAGS (MULTIBOOT_PAGE_ALIGN | MULTIBOOT_MEMORY_INFO | MULTIBOOT_VIDEO_MODE)
#define CHECKSUM -(MULTIBOOT_HEADER_MAGIC + FLAGS)

    .section .multiboot, "a", @progbits
    .align MULTIBOOT_HEADER_ALIGN
    .long MULTIBOOT_HEADER_MAGIC
    .long FLAGS
    .long CHECKSUM

    // MULTIBOOT_AOUT_KLUDGE
    .long 0 // header_addr
    .long 0 // load_addr
    .long 0 // load_end_addr
    .long 0 // bss_end_addr
    .long 0 // entry_addr

    // MULTIBOOT_VIDEO_MODE
    .long 0  // mode_type
    .long 0  // width
    .long 0  // height
    .long 32 // depth

    .section .init_text, "ax", @progbits
    .globl _start
_start:
    .code32
    cli
    cld

    # Virtual address    Physical address      Size Description
    # 0x0000000000000000 0x0000000000000000   4 MiB identity mapping
    # 0xffffff0000000000 pml4t              512 GiB recursive mapping of PML4T
    # 0xffffffffc0000000 0x0000000000000000   4 MiB higher half kernel

    # Page table (mapping first 4 MiB of physical memory)
    movl $(PTE_PRESENT | PTE_WRITE | PTE_GLOBAL), %esi
    movl $pt, %edi
    movl $1024, %ecx
1:
    movl %esi, (%edi)
    addl $PAGE_SIZE, %esi
    addl $8, %edi
    loop 1b

    # Save parameters from Multiboot
    movl %eax, %edi
    movl %ebx, %esi

    # PDE (mapping 1st 2 MiB)
    movl $pt, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pd

    # PDE (mapping 2nd 2 MiB)
    movl $pt2, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pd + 8

    # PDPTE (identity mapping and higher half)
    movl $pd, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pdpt_identity
    movl %eax, pdpt_high + 511 * 8

    # PML4TE (identity mapping)
    movl $pdpt_identity, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pml4t

    # PML4TE (recursive mapping)
    movl $pml4t, %eax
    orl $(PTE_PRESENT | PTE_WRITE), %eax
    movl %eax, pml4t + RECURSIVE_MAPPING_INDEX * 8

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

    jmp high_memory_start

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

    .align 16
ap_initial_gdt:
    .long 0, 0
    .long 0x0000ffff, 0x00cf9a00 # code
    .long 0x0000ffff, 0x00cf9200 # data
ap_initial_gdtr:
    .word ap_initial_gdtr - ap_initial_gdt - 1
    .long ap_initial_gdt - ap_trampoline_start + AP_TRAMPOLINE_ADDR

    .align 32
    .code32
ap_trampoline_start32:
    movl $kernel_page_table_start, %eax
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
    #movl ap_stack_top, %esp
    subl %eax, %esp

    #pushl $loop_forever # return address

    .extern ap_start
    .type ap_start, @function
    #ljmp $8, $ap_start
    ud2
ap_trampoline_end:

    .section .init_rodata, "a", @progbits
gdt64:
    .quad 0
    .quad (1<<43) | (1<<44) | (1<<47) | (1<<53) // executable, code segment, present, 64-bit
gdtr64:
    .short . - gdt64 - 1
    .quad gdt64

    .section .init_bss, "aw", @nobits
    .globl kernel_page_table_start
kernel_page_table_start:
    .align PAGE_SIZE
pml4t:
    .skip PAGE_SIZE
pdpt_identity:
    .skip PAGE_SIZE
pdpt_high:
    .skip PAGE_SIZE
pd:
    .skip PAGE_SIZE
pt:
    .skip PAGE_SIZE
pt2:
    .skip PAGE_SIZE

    .text
    .code64
high_memory_start:
    # remove identity mapping
    movq $0, pml4t + KERNEL_IMAGE_ADDR
    movq $0, pdpt_identity + KERNEL_IMAGE_ADDR
    movq $pml4t, %rax
    movq %rax, %cr3

    mov $initial_kernel_stack_top, %rsp
    call start

loop_forever:
    cli
1:
    hlt
    jmp 1b

    .globl read_eip
read_eip:
    pop %rax
    jmp *%rax

    .bss
    .globl initial_kernel_stack_base, initial_kernel_stack_top
    .align PAGE_SIZE
initial_kernel_stack_base:
    .skip STACK_SIZE
initial_kernel_stack_top:

ap_id:
    .long 0
