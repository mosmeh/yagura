#pragma once

#include <arch/system.h>
#include <kernel/api/sys/types.h>
#include <kernel/drivers/graphics/graphics.h>

struct timespec;

struct boot_params {
    phys_addr_t initramfs_addr;
    size_t initramfs_size;
    struct fb_info fb_info;
};

extern struct boot_params boot_params;

void arch_late_init(void);

// Attempts to reboot the system.
// If rebooting is not supported or the attempt fails, returns to the caller.
void arch_reboot(void);

// Attempts to power off the system.
// If power-off is not supported or the attempt fails, returns to the caller.
void arch_poweroff(void);

NODISCARD bool arch_random_init(void);
NODISCARD ssize_t arch_random_get(void* buffer, size_t count);

// Retrieves the current wall-clock time.
void arch_time_now(struct timespec*);

bool arch_smp_active(void);
