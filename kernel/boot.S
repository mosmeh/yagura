#define ASM_FILE
#include "multiboot.h"
#include "api/asm/processor-flags.h"
#include "system.h"
#include "memory/memory.h"

#define FLAGS (MULTIBOOT_PAGE_ALIGN | MULTIBOOT_MEMORY_INFO | MULTIBOOT_VIDEO_MODE)
#define CHECKSUM -(MULTIBOOT_HEADER_MAGIC + FLAGS)

    .section .multiboot, "a"
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

    .section .init_text, "a"
    .globl _start
_start:
    cli

    # fill page table
    movl $(PTE_PRESENT | PTE_WRITE | PTE_GLOBAL), %esi
    movl $kernel_page_table_start, %edi
    movl $1022, %ecx # last two pages are for quickmap
1:
    movl %esi, (%edi)
    addl $PAGE_SIZE, %esi
    addl $4, %edi
    loop 1b

    movl $kernel_page_table_start, %edx
    orl $(PTE_PRESENT | PTE_WRITE), %edx
    movl %edx, kernel_page_directory_start # identity mapping
    movl %edx, kernel_page_directory_start + KERNEL_PDE_IDX * 4

    # recursive
    movl $kernel_page_directory_start, %edx
    orl $(PTE_PRESENT | PTE_WRITE), %edx
    movl %edx, kernel_page_directory_start + 1023 * 4

    movl $kernel_page_directory_start, %edx
    movl %edx, %cr3

    movl %cr0, %edx
    orl $(X86_CR0_PG | X86_CR0_WP), %edx
    movl %edx, %cr0

    lea paging_enabled, %edx
    jmp *%edx

    .section .init_bss, "aw", @nobits
    .globl kernel_page_directory_start
    .align PAGE_SIZE
kernel_page_directory_start:
    .skip PAGE_SIZE
    .align PAGE_SIZE
kernel_page_table_start:
    .skip PAGE_SIZE

    .text
paging_enabled:
    # remove identity mapping
    movl $0, kernel_page_directory_start + KERNEL_VIRT_ADDR
    movl $kernel_page_directory_start, %edx
    movl %edx, %cr3

    movl $initial_kernel_stack_top, %esp
    pushl %ebx # Multiboot info struct
    pushl %eax # Multiboot magic

    call start

    cli
loop_forever:
    hlt
    jmp loop_forever

    .globl read_eip
read_eip:
    popl %eax
    jmp *%eax

    .code16
    .globl ap_trampoline_start, ap_trampoline_end
ap_trampoline_start:
    cli

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
    movl $kernel_page_directory_start, %eax
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

    pushl $loop_forever # return address

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
