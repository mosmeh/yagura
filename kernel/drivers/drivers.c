#include <kernel/drivers/drivers.h>

void acpi_init(void);
void serial_late_init(void);
void ps2_init(void);
void fb_init(void);
void virtio_blk_init(void);
void ac97_init(void);

void drivers_init(void) {
    acpi_init();
    serial_late_init();
    ps2_init();
    fb_init();
    virtio_blk_init();
    ac97_init();
}
