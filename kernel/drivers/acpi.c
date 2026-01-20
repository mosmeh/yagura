#include <common/string.h>
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

struct rsdp_descriptor_2 {
    struct rsdp_descriptor rsdp;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t extended_checksum;
    uint8_t reserved[3];
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

struct xsdt {
    struct sdt_header header;
    uint64_t entries[];
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

struct generic_address_structure {
    uint8_t address_space;
    uint8_t bit_width;
    uint8_t bit_offset;
    uint8_t access_size;
    uint64_t address;
} __attribute__((packed));

#define GENERIC_ADDRESS_SPACE_SYSTEM_IO 1

struct fadt {
    struct sdt_header header;
    uint32_t firmware_ctrl;
    uint32_t dsdt_ptr;
    uint8_t reserved;
    uint8_t preferred_pm_profile;
    uint16_t sci_int;
    uint32_t smi_cmd;
    uint8_t acpi_enable_value;
    uint8_t acpi_disable_value;
    uint8_t s4bios_req;
    uint8_t pstate_cnt;
    uint32_t pm1a_evt_blk;
    uint32_t pm1b_evt_blk;
    uint32_t pm1a_cnt_blk;
    uint32_t pm1b_cnt_blk;
    uint32_t pm2_cnt_blk;
    uint32_t pm_tmr_blk;
    uint32_t gpe0_blk;
    uint32_t gpe1_blk;
    uint8_t pm1_evt_len;
    uint8_t pm1_cnt_len;
    uint8_t pm2_cnt_len;
    uint8_t pm_tmr_len;
    uint8_t gpe0_blk_len;
    uint8_t gpe1_blk_len;
    uint8_t gpe1_base;
    uint8_t cst_cnt;
    uint16_t p_lvl2_lat;
    uint16_t p_lvl3_lat;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t duty_offset;
    uint8_t duty_width;
    uint8_t day_alrm;
    uint8_t mon_alrm;
    uint8_t century;
    uint16_t ia_pc_boot_arch_flags;
    uint8_t reserved2;
    uint32_t flags;
    struct generic_address_structure reset_reg;
    uint8_t reset_value;
    uint16_t arm_boot_arch;
    uint8_t fadt_minor_version;
    uint64_t x_firmware_ctrl;
    uint64_t x_dsdt;
    struct generic_address_structure x_pm1a_evt_blk;
    struct generic_address_structure x_pm1b_evt_blk;
    struct generic_address_structure x_pm1a_cnt_blk;
    struct generic_address_structure x_pm1b_cnt_blk;
    struct generic_address_structure x_pm2_cnt_blk;
    struct generic_address_structure x_pm_tmr_blk;
    struct generic_address_structure x_gpe0_blk;
    struct generic_address_structure x_gpe1_blk;
    struct generic_address_structure sleep_control;
    struct generic_address_structure sleep_status;
    uint64_t hypervisor_vendor_identity;
} __attribute__((packed));

static const struct rsdp_descriptor* find_rsdp(void) {
    const uint64_t* p = (const uint64_t*)(0x80000 + KERNEL_IMAGE_START);
    const uint64_t* end = (const uint64_t*)(0x100000 + KERNEL_IMAGE_START);
    for (; p < end; p += 2) {         // Signature is at 16-byte boundary
        if (*p == 0x2052545020445352) // "RSD PTR "
            return (const struct rsdp_descriptor*)p;
    }
    return NULL;
}

static struct rsdt* map_rsdt(const struct rsdp_descriptor* rsdp) {
    if (!rsdp->rsdt_address)
        return NULL;

    phys_addr_t phys_addr = rsdp->rsdt_address;
    if (phys_addr != rsdp->rsdt_address)
        return NULL; // Address does not fit in phys_addr_t

    struct rsdt* header = phys_map(phys_addr, sizeof(struct rsdt), VM_READ);
    ASSERT_PTR(header);
    uint32_t size = header->header.length;
    phys_unmap(header);

    if (size < sizeof(struct rsdt))
        return NULL;

    return phys_map(phys_addr, size, VM_READ);
}

static struct xsdt* map_xsdt(const struct rsdp_descriptor* rsdp) {
    if (rsdp->revision < 2)
        return NULL;

    const struct rsdp_descriptor_2* rsdp2 = (const void*)rsdp;
    if (rsdp2->length < sizeof(struct rsdp_descriptor_2) ||
        !rsdp2->xsdt_address)
        return NULL;

    phys_addr_t phys_addr = rsdp2->xsdt_address;
    if (phys_addr != rsdp2->xsdt_address)
        return NULL; // Address does not fit in phys_addr_t

    struct xsdt* header = phys_map(phys_addr, sizeof(struct xsdt), VM_READ);
    ASSERT_PTR(header);
    uint32_t size = header->header.length;
    phys_unmap(header);

    if (size < sizeof(struct xsdt))
        return NULL;

    return phys_map(phys_addr, size, VM_READ);
}

#define SIGNATURE_SIZE SIZEOF_FIELD(struct sdt_header, signature)

// Returns the length of the table if the signature matches, 0 otherwise
static size_t match_signature(phys_addr_t addr,
                              const char signature[static SIGNATURE_SIZE]) {
    struct sdt_header* header =
        phys_map(addr, sizeof(struct sdt_header), VM_READ);
    ASSERT_PTR(header);
    bool match =
        !memcmp(header->signature, signature, sizeof(header->signature));
    uint32_t length = header->length;
    phys_unmap(header);
    return match ? length : 0;
}

static void* map_table_in_rsdt(const struct rsdt* rsdt,
                               const char signature[static SIGNATURE_SIZE]) {
    size_t entries_size = rsdt->header.length - sizeof(struct sdt_header);
    size_t n = entries_size / sizeof(uint32_t);
    for (size_t i = 0; i < n; ++i) {
        phys_addr_t phys_addr = rsdt->entries[i];
        if (phys_addr != rsdt->entries[i])
            continue; // Address does not fit in phys_addr_t
        size_t length = match_signature(phys_addr, signature);
        if (length >= sizeof(struct sdt_header))
            return phys_map(phys_addr, length, VM_READ);
    }
    return NULL;
}

static void* map_table_in_xsdt(const struct xsdt* xsdt,
                               const char signature[static SIGNATURE_SIZE]) {
    size_t entries_size = xsdt->header.length - sizeof(struct sdt_header);
    size_t n = entries_size / sizeof(uint64_t);
    for (size_t i = 0; i < n; ++i) {
        phys_addr_t phys_addr = xsdt->entries[i];
        if (phys_addr != xsdt->entries[i])
            continue; // Address does not fit in phys_addr_t
        size_t length = match_signature(phys_addr, signature);
        if (length >= sizeof(struct sdt_header))
            return phys_map(phys_addr, length, VM_READ);
    }
    return NULL;
}

static void* map_table(const struct rsdp_descriptor* rsdp,
                       const char signature[static SIGNATURE_SIZE]) {
    struct xsdt* xsdt = map_xsdt(rsdp);
    ASSERT_OK(xsdt);
    if (xsdt) {
        void* table = map_table_in_xsdt(xsdt, signature);
        ASSERT_OK(table);
        phys_unmap(xsdt);
        if (table)
            return table;
    }

    struct rsdt* rsdt = map_rsdt(rsdp);
    ASSERT_OK(rsdt);
    if (rsdt) {
        void* table = map_table_in_rsdt(rsdt, signature);
        ASSERT_OK(table);
        phys_unmap(rsdt);
        if (table)
            return table;
    }

    return NULL;
}

static struct acpi acpi;

static void parse_madt(const struct rsdp_descriptor* rsdp) {
    const struct madt* madt = map_table(rsdp, "APIC");
    ASSERT_OK(madt);

    size_t num_local_apics = 0;
    size_t num_io_apics = 0;
    size_t num_interrupt_source_overrides = 0;

    if (madt) {
        acpi.lapic_addr = madt->lapic_addr;

        const unsigned char* p = (const unsigned char*)madt->structures;
        const unsigned char* end =
            (const unsigned char*)madt + madt->header.length;

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
    }

    // +1 for sentinel NULL pointers
    size_t total = (num_local_apics + 1) + (num_io_apics + 1) +
                   (num_interrupt_source_overrides + 1);
    void** buf = kmalloc(total * sizeof(void*));
    ASSERT(buf);
    size_t offset = 0;
    acpi.local_apics = (void*)(buf + offset);
    offset += num_local_apics + 1;
    acpi.io_apics = (void*)(buf + offset);
    offset += num_io_apics + 1;
    acpi.interrupt_source_overrides = (void*)(buf + offset);

    const struct local_apic** local_apic = acpi.local_apics;
    const struct io_apic** io_apic = acpi.io_apics;
    const struct interrupt_source_override** interrupt_source_override =
        acpi.interrupt_source_overrides;

    if (madt) {
        const unsigned char* p = (const unsigned char*)madt->structures;
        const unsigned char* end =
            (const unsigned char*)madt + madt->header.length;
        while (p < end) {
            const struct ics_header* header = (const struct ics_header*)p;
            switch (header->type) {
            case ACPI_MADT_LAPIC:
                *local_apic++ = (const void*)p;
                break;
            case ACPI_MADT_IO_APIC:
                *io_apic++ = (const void*)p;
                break;
            case ACPI_MADT_INTERRUPT_SOURCE_OVERRIDE:
                *interrupt_source_override++ = (const void*)p;
                break;
            }
            p += header->length;
        }
    }

    // Sentinels
    *local_apic = NULL;
    *io_apic = NULL;
    *interrupt_source_override = NULL;

    if (num_local_apics > 0) {
        kprint("acpi: found CPUs ");
        for (const struct local_apic** p = acpi.local_apics; *p; ++p) {
            if (!((*p)->flags &
                  (ACPI_LOCAL_APIC_ENABLED | ACPI_LOCAL_APIC_ONLINE_CAPABLE)))
                continue;
            kprintf("%u ", (*p)->apic_id);
        }
        kprint("\n");
    }
}

static void parse_fadt(const struct rsdp_descriptor* rsdp) {
    struct fadt* fadt = map_table(rsdp, "FACP");
    ASSERT_OK(fadt);
    if (fadt) {
        if (fadt->reset_reg.address_space == GENERIC_ADDRESS_SPACE_SYSTEM_IO) {
            acpi.reset_port = fadt->reset_reg.address;
            acpi.reset_value = fadt->reset_value;
        }
        phys_unmap(fadt);
    }
}

static bool is_parse_successful = false;

void acpi_init(void) {
    const struct rsdp_descriptor* rsdp = find_rsdp();
    if (!rsdp)
        return;

    parse_madt(rsdp);
    parse_fadt(rsdp);

    is_parse_successful = true;
}

const struct acpi* acpi_get(void) { return is_parse_successful ? &acpi : NULL; }
