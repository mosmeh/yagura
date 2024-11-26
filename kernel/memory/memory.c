#include "memory.h"
#include "private.h"

void memory_init(const multiboot_info_t* mb_info) {
    page_init(mb_info);
    vm_init();
    vm_obj_init();
}
