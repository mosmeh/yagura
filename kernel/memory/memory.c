#include "memory.h"
#include "private.h"

void memory_init(const multiboot_info_t* mb_info) {
    uintptr_t kernel_vm_start = page_init(mb_info);
    vm_init(kernel_vm_start);
    vm_obj_init();
}
