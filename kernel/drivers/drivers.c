#include "drivers.h"
#include <kernel/multiboot.h>

void pit_init(void);
void pseudo_devices_init(void);
void serial_late_init(void);
void ps2_init(void);
void fb_init(const multiboot_info_t*);
void ac97_init(void);

void drivers_init(const multiboot_info_t* mb_info) {
    pit_init();
    pseudo_devices_init();
    serial_late_init();
    ps2_init();
    fb_init(mb_info);
    ac97_init();
}
