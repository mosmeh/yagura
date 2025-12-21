#include <common/string.h>
#include <kernel/cpu.h>
#include <kernel/drivers/acpi.h>
#include <kernel/kmsg.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>

struct rsdp_descriptor {
    char signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_address;
} __attribute__((packed));

struct sdt_header {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed));

struct rsdt {
    struct sdt_header header;
    uint32_t entries[];
} __attribute__((packed));

struct madt {
    struct sdt_header header;
    uint32_t lapic_addr;
    uint32_t flags;
    uint8_t structures[];
} __attribute__((packed));

#define ACPI_MADT_LAPIC 0
#define ACPI_MADT_IO_APIC 1
#define ACPI_MADT_INTERRUPT_SOURCE_OVERRIDE 2

static const struct rsdp_descriptor* find_rsdp(void) {
    uint64_t* p = (uint64_t*)(0x80000 + KERNEL_VIRT_ADDR);
    uint64_t* end = (uint64_t*)(0x100000 + KERNEL_VIRT_ADDR);
    for (; p < end; p += 2) {         // Signature is at 16-byte boundary
        if (*p == 0x2052545020445352) // "RSD PTR "
            return (struct rsdp_descriptor*)p;
    }
    return NULL;
}

static struct madt* find_madt(const struct rsdt* rsdt) {
    size_t n =
        (rsdt->header.length - sizeof(struct sdt_header)) / sizeof(uint32_t);
    for (size_t i = 0; i < n; ++i) {
        struct sdt_header* header =
            phys_map(rsdt->entries[i], sizeof(struct sdt_header), VM_READ);
        ASSERT_PTR(header);

        uint32_t signature;
        memcpy(&signature, header->signature, sizeof(signature));
        uint32_t length = header->length;
        phys_unmap(header);
        if (signature == 0x43495041) // "APIC"
            return phys_map(rsdt->entries[i], length, VM_READ);
    }
    return NULL;
}

static bool is_parse_successful = false;
static struct acpi acpi;

void acpi_init(void) {
    const struct rsdp_descriptor* rsdp = find_rsdp();
    if (!rsdp)
        return;

    struct rsdt* rsdt_header =
        phys_map(rsdp->rsdt_address, sizeof(struct rsdt), VM_READ);
    ASSERT_PTR(rsdt_header);
    uint32_t rsdt_size = rsdt_header->header.length;
    phys_unmap(rsdt_header);

    struct rsdt* rsdt = phys_map(rsdp->rsdt_address, rsdt_size, VM_READ);
    ASSERT_PTR(rsdt);

    struct madt* madt = find_madt(rsdt);
    ASSERT_OK(madt);
    phys_unmap(rsdt);
    if (!madt)
        return;

    acpi.lapic_addr = madt->lapic_addr;

    unsigned char* p = (unsigned char*)madt->structures;
    unsigned char* end = (unsigned char*)madt + madt->header.length;

    // Includes the sentinels
    size_t num_local_apics = 1;
    size_t num_io_apics = 1;
    size_t num_interrupt_source_overrides = 1;

    while (p < end) {
        const struct ics_header* header = (const struct ics_header*)p;
        switch (header->type) {
        case ACPI_MADT_LAPIC:
            ++num_local_apics;
            break;
        case ACPI_MADT_IO_APIC:
            ++num_io_apics;
            break;
        case ACPI_MADT_INTERRUPT_SOURCE_OVERRIDE:
            ++num_interrupt_source_overrides;
            break;
        }
        p += header->length;
    }

    size_t total =
        num_local_apics + num_io_apics + num_interrupt_source_overrides;
    void** buf = kmalloc(total * sizeof(void*));
    ASSERT(buf);
    size_t offset = 0;
    acpi.local_apics = (void*)(buf + offset);
    offset += num_local_apics;
    acpi.io_apics = (void*)(buf + offset);
    offset += num_io_apics;
    acpi.interrupt_source_overrides = (void*)(buf + offset);

    p = (unsigned char*)madt->structures;
    const struct local_apic** local_apic = acpi.local_apics;
    const struct io_apic** io_apic = acpi.io_apics;
    const struct interrupt_source_override** interrupt_source_override =
        acpi.interrupt_source_overrides;
    while (p < end) {
        const struct ics_header* header = (const struct ics_header*)p;
        switch (header->type) {
        case ACPI_MADT_LAPIC:
            *local_apic++ = (const struct local_apic*)p;
            break;
        case ACPI_MADT_IO_APIC:
            *io_apic++ = (const struct io_apic*)p;
            break;
        case ACPI_MADT_INTERRUPT_SOURCE_OVERRIDE:
            *interrupt_source_override++ =
                (const struct interrupt_source_override*)p;
            break;
        }
        p += header->length;
    }

    // Sentinels
    *local_apic = NULL;
    *io_apic = NULL;
    *interrupt_source_override = NULL;

    kprint("acpi: found CPUs ");
    for (const struct local_apic** p = acpi.local_apics; *p; ++p)
        kprintf("%u ", (*p)->apic_id);
    kprintf("(BSP = %u)\n", cpu_get_bsp()->apic_id);

    is_parse_successful = true;
}

const struct acpi* acpi_get(void) { return is_parse_successful ? &acpi : NULL; }
