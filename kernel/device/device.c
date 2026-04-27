#include "private.h"
#include <kernel/device/device.h>

void device_init(void) {
    block_dev_init();
    pseudo_devices_init();
}
