#define ASM_FILE
#include <kernel/arch/x86/boot/multiboot.h>

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
