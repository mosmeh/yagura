#include <kernel/arch/system.h>
#include <kernel/arch/x86/interrupts/interrupts.h>
#include <kernel/drivers/acpi.h>
#include <kernel/drivers/hid/ps2.h>

void arch_reboot(void) {
    const struct acpi* acpi = acpi_get();
    if (acpi && acpi->reset_port)
        out8(acpi->reset_port, acpi->reset_value);

    // If ACPI reset didn't work, try keyboard controller reset
    out8(PS2_COMMAND, 0xfe);

    // If keyboard controller didn't work, cause a triple fault
    idt_invalidate();
    __asm__ volatile("int3");
}

void arch_poweroff(void) {
    // this works only on emulators
    out16(0x604, 0x2000);  // QEMU
    out16(0x4004, 0x3400); // Virtualbox
    out16(0xb004, 0x2000); // Bochs and older versions of QEMU
}
