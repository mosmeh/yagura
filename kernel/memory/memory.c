#include "memory.h"
#include "private.h"

void memory_init(const multiboot_info_t* mb_info) {
    page_init(mb_info);
    page_table_init();
    vm_init();
}
