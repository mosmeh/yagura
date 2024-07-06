#include "boot_defs.h"
#define ASM_FILE
#include "multiboot.h"

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
  movl $0x103, %esi # P | RW | G
  movl $kernel_page_table_start, %edi
  movl $1022, %ecx # last two pages are for quickmap
1:
  movl %esi, (%edi)
  addl $PAGE_SIZE, %esi
  addl $4, %edi
  loop 1b

  movl $kernel_page_table_start, %edx
  orl $3, %edx # P | RW
  movl %edx, kernel_page_directory_start # identity mapping
  movl %edx, kernel_page_directory_start + KERNEL_PDE_IDX * 4

  # recursive
  movl $kernel_page_directory_start, %edx
  orl $3, %edx # P | RW
  movl %edx, kernel_page_directory_start + 1023 * 4

  movl $kernel_page_directory_start, %edx
  movl %edx, %cr3

  # set PG | WP
  movl %cr0, %edx
  orl $0x80010000, %edx
  movl %edx, %cr0

  lea paging_enabled, %edx
  jmp *%edx

  .section .init_bss, "aw", @nobits
  .globl kernel_page_directory_start
kernel_page_directory_start:
  .align PAGE_SIZE
  .skip PAGE_SIZE
kernel_page_table_start:
  .align PAGE_SIZE
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

  .globl initial_kernel_stack_base, initial_kernel_stack_top
initial_kernel_stack_base:
  .section .stack, "aw", @nobits
  .skip STACK_SIZE
initial_kernel_stack_top:
