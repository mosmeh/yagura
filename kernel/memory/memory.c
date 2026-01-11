#include "private.h"
#include <kernel/memory/memory.h>

void memory_init(void) {
    vm_init();
    vm_region_init();
    phys_init();
    vm_obj_init();
}
