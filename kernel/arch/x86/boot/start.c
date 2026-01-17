#include <kernel/arch/system.h>
#include <kernel/arch/x86/boot/multiboot.h>
#include <kernel/arch/x86/cpu.h>
#include <kernel/arch/x86/interrupts/interrupts.h>
#include <kernel/arch/x86/smp.h>
#include <kernel/arch/x86/syscall/syscall.h>
#include <kernel/cpu.h>
#include <kernel/drivers/serial.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/memory/phys.h>
#include <kernel/system.h>

struct boot_params boot_params;
static multiboot_module_t initrd_mod;

static void* low_phys_to_virt(phys_addr_t phys_addr) {
    return (void*)((uintptr_t)phys_addr + KERNEL_IMAGE_START);
}

_Noreturn void start(uint32_t mb_magic, phys_addr_t mb_info_phys_addr) {
    gdt_init_cpu();
    cpu_init_features();
    idt_init();
    i8259_init();
    serial_early_init();

    ASSERT(mb_magic == MULTIBOOT_BOOTLOADER_MAGIC);
    const multiboot_info_t* mb = low_phys_to_virt(mb_info_phys_addr);

    if (mb->flags & MULTIBOOT_INFO_CMDLINE)
        cmdline_init(low_phys_to_virt(mb->cmdline));

    if (mb->flags & MULTIBOOT_INFO_MODS) {
        const multiboot_module_t* mod = low_phys_to_virt(mb->mods_addr);
        if (mb->mods_count > 0)
            initrd_mod = *mod;
        for (uint32_t i = 0; i < mb->mods_count; ++i, ++mod)
            phys_range_add_reserved("module", mod->mod_start,
                                    mod->mod_end - mod->mod_start);
    }

    if (mb->flags & MULTIBOOT_INFO_MEM_MAP) {
        uint32_t num_entries = mb->mmap_length / sizeof(multiboot_memory_map_t);
        const multiboot_memory_map_t* entry = low_phys_to_virt(mb->mmap_addr);
        for (uint32_t i = 0; i < num_entries; ++i, ++entry) {
            if (entry->len == 0)
                continue;

            phys_addr_t start = entry->addr;
            if (start != entry->addr)
                continue; // Address does not fit in phys_addr_t

            uint64_t end = entry->addr + entry->len;
            if (end < entry->addr) // Overflow
                end = UINT64_MAX;

            size_t size = MIN(end, SIZE_MAX) - entry->addr;

            switch (entry->type) {
            case MULTIBOOT_MEMORY_AVAILABLE:
                phys_range_add_available(start, size);
                break;
            case MULTIBOOT_MEMORY_RESERVED:
                phys_range_add_reserved("reserved", start, size);
                break;
            case MULTIBOOT_MEMORY_ACPI_RECLAIMABLE:
                phys_range_add_reserved("ACPI reclaimable", start, size);
                break;
            case MULTIBOOT_MEMORY_NVS:
                phys_range_add_reserved("NVS", start, size);
                break;
            case MULTIBOOT_MEMORY_BADRAM:
                phys_range_add_reserved("bad RAM", start, size);
                break;
            }
        }
    } else {
        kprint("x86: no memory map provided by bootloader\n");
        phys_range_add_available(0x100000, (size_t)mb->mem_upper * 0x400);
    }

    if ((mb->flags & MULTIBOOT_INFO_FRAMEBUFFER_INFO) &&
        mb->framebuffer_type == MULTIBOOT_FRAMEBUFFER_TYPE_RGB) {
        boot_params.fb_info = (struct fb_info){
            .id = "multiboot",
            .phys_addr = mb->framebuffer_addr,
            .width = mb->framebuffer_width,
            .height = mb->framebuffer_height,
            .pitch = mb->framebuffer_pitch,
            .bpp = mb->framebuffer_bpp,
        };
    }

    pit_init();
    kernel_main();
}

void arch_late_init(void) {
    if (initrd_mod.mod_start < initrd_mod.mod_end)
        initrd_populate_root_fs(initrd_mod.mod_start,
                                initrd_mod.mod_end - initrd_mod.mod_start);

    syscall_init();
    smp_init();
}
