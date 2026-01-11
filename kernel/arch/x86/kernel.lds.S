#include <kernel/memory/memory.h>

ENTRY (_start)

PHDRS {
    multiboot PT_LOAD;
    init_text PT_LOAD;
    init_bss PT_LOAD;
    text PT_LOAD;
    data PT_LOAD;
    bss PT_LOAD;
}

SECTIONS {
    . = 0x100000;

    .multiboot : AT(ADDR(.multiboot)) {
        KEEP(*(.multiboot))
    } :multiboot

    .init_text : AT(ADDR(.init_text)) {
        *(.init_text)
    } :init_text

    .init_bss : AT(ADDR(.init_bss)) {
        *(.init_bss)
    } :init_bss

    init_end = .;

    . += KERNEL_IMAGE_START;

    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_IMAGE_START) {
        *(.text)
    } :text

    .rodata ALIGN (4K) : AT(ADDR(.rodata) - KERNEL_IMAGE_START) {
        *(.rodata)
    } :data

    .data ALIGN (4K) : AT(ADDR(.data) - KERNEL_IMAGE_START) {
        *(.data)
    } :data

    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_IMAGE_START) {
        *(COMMON)
        *(.bss)
    } :bss

    kernel_end = .;
}
