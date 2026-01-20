#pragma once

#include <common/stddef.h>
#include <common/stdint.h>

struct ics_header {
    uint8_t type;
    uint8_t length;
} __attribute__((packed));

#define ACPI_LOCAL_APIC_ENABLED 0x1
#define ACPI_LOCAL_APIC_ONLINE_CAPABLE 0x2

struct local_apic {
    struct ics_header header;
    uint8_t acpi_processor_uid;
    uint8_t apic_id;
    uint32_t flags;
} __attribute__((packed));

struct io_apic {
    struct ics_header header;
    uint8_t io_apic_id;
    uint8_t reserved;
    uint32_t io_apic_addr;
    uint32_t global_system_interrupt_base;
} __attribute__((packed));

struct interrupt_source_override {
    struct ics_header header;
    uint8_t bus;
    uint8_t source;
    uint32_t global_system_interrupt;
    uint16_t flags;
} __attribute__((packed));

struct acpi {
    uintptr_t lapic_addr;

    uint16_t reset_port;
    uint8_t reset_value;

    // Null-terminated arrays of pointers to the respective structures
    const struct local_apic** local_apics;
    const struct io_apic** io_apics;
    const struct interrupt_source_override** interrupt_source_overrides;
};

const struct acpi* acpi_get(void);
