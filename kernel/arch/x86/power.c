#include <kernel/arch/system.h>
#include <kernel/drivers/hid/ps2.h>

void arch_reboot(void) { out8(PS2_COMMAND, 0xfe); }

void arch_poweroff(void) {
    // this works only on emulators
    out16(0x604, 0x2000);  // QEMU
    out16(0x4004, 0x3400); // Virtualbox
    out16(0xb004, 0x2000); // Bochs and older versions of QEMU
}
