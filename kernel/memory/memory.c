#include "memory.h"
#include "private.h"

void memory_init(const multiboot_info_t* mb_info) {
    size_t kernel_heap_start = page_init(mb_info);
    vm_init(kernel_heap_start);
    kmalloc_init();
}
