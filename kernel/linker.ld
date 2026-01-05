ENTRY (_start)

PHDRS {
  multiboot PT_LOAD;
  init_text PT_LOAD;
  init_rodata PT_LOAD;
  init_bss PT_LOAD;
  text PT_LOAD;
  data PT_LOAD;
  bss PT_LOAD;
}

KERNEL_IMAGE_ADDR = 0xffffffffc0000000;

SECTIONS {
    . = 0x100000;

    .multiboot : AT(ADDR(.multiboot)) {
        KEEP(*(.multiboot))
    } :multiboot

    .init_text : AT(ADDR(.init_text)) {
        *(.init_text)
    } :init_text

    .init_rodata : AT(ADDR(.init_rodata)) {
        *(.init_rodata)
    } :init_rodata

    .init_bss : AT(ADDR(.init_bss)) {
        *(.init_bss)
    } :init_bss

    init_end = .;

    . += KERNEL_IMAGE_ADDR;

    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_IMAGE_ADDR) {
        *(.text)
    } :text

    .rodata ALIGN (4K) : AT(ADDR(.rodata) - KERNEL_IMAGE_ADDR) {
        *(.rodata)
    } :data

    .data ALIGN (4K) : AT(ADDR(.data) - KERNEL_IMAGE_ADDR) {
        *(.data)
    } :data

    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_IMAGE_ADDR) {
        *(COMMON)
        *(.bss)
    } :bss

    kernel_end = .;
}
