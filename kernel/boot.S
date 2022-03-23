#include "boot_defs.h"
#define ASM_FILE
#include "multiboot.h"

#define FLAGS (MULTIBOOT_PAGE_ALIGN | MULTIBOOT_MEMORY_INFO)
#define CHECKSUM -(MULTIBOOT_HEADER_MAGIC + FLAGS)

  .section .multiboot, "a"
  .align MULTIBOOT_HEADER_ALIGN
  .long MULTIBOOT_HEADER_MAGIC
  .long FLAGS
  .long CHECKSUM

  // MULTIBOOT_MEMORY_INFO
  .long 0 // header_addr
  .long 0 // load_addr
  .long 0 // load_end_addr
  .long 0 // bss_end_addr
  .long 0 // entry_addr

  .section .init_text, "a"
  .globl _start
_start:
  cli

  # fill page table
  movl $7, %esi # P | RW | US
  movl $init_page_table, %edi
  movl $1023, %ecx # last page is for quickmap
1:
  movl %esi, (%edi)
  addl $PAGE_SIZE, %esi
  addl $4, %edi
  loop 1b

  movl $init_page_table, %edx
  orl $7, %edx # P | RW | US
  movl %edx, init_page_directory # identity mapping
  movl %edx, init_page_directory + KERNEL_PDE_IDX * 4

  # recursive
  movl $init_page_directory, %edx
  orl $3, %edx # P | RW
  movl %edx, init_page_directory + 1023 * 4

  movl $init_page_directory, %edx
  movl %edx, %cr3

  # set PG | WP
  movl %cr0, %edx
  orl $0x80010000, %edx
  movl %edx, %cr0

  lea paging_enabled, %edx
  jmp *%edx

  .section .init_bss, "aw", @nobits
init_page_directory:
  .align PAGE_SIZE
  .skip PAGE_SIZE
init_page_table:
  .align PAGE_SIZE
  .skip PAGE_SIZE

  .text
paging_enabled:
  # remove identity mapping
  movl $0, init_page_directory + KERNEL_VADDR
  movl $init_page_directory, %edx
  movl %edx, %cr3

  movl $stack_top, %esp
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

  .section .stack, "aw", @nobits
  .skip STACK_SIZE
  .globl stack_top
stack_top:
