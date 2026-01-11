#include <kernel/arch/io.h>
#include <kernel/drivers/pci.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>

#define PCI_ADDRESS_PORT 0xcf8
#define PCI_VALUE_PORT 0xcfc

#define PCI_VENDOR_ID 0x00
#define PCI_COMMAND 0x04
#define PCI_STATUS 0x06
#define PCI_DEVICE_ID 0x02
#define PCI_SUBCLASS 0x0a
#define PCI_CLASS 0x0b
#define PCI_HEADER_TYPE 0x0e
#define PCI_BAR0 0x10
#define PCI_BAR1 0x14
#define PCI_BAR2 0x18
#define PCI_SECONDARY_BUS 0x19
#define PCI_BAR3 0x1c
#define PCI_BAR4 0x20
#define PCI_BAR5 0x24
#define PCI_CAPABILITIES_POINTER 0x34
#define PCI_INTERRUPT_LINE 0x3c

#define PCI_TYPE_BRIDGE 0x604
#define PCI_NONE 0xffff

#define PCI_COMMAND_IO_SPACE 0x1
#define PCI_COMMAND_BUS_MASTER 0x4
#define PCI_COMMAND_INTERRUPT_DISABLE 0x400

#define PCI_STATUS_CAPABILITIES_LIST 0x10

static uint32_t io_address_for_field(const struct pci_addr* addr,
                                     uint8_t field) {
    return 0x80000000 | ((uint32_t)addr->bus << 16) |
           ((uint32_t)addr->slot << 11) | ((uint32_t)addr->function << 8) |
           (field & 0xfc);
}

uint8_t pci_read_field8(const struct pci_addr* addr, uint8_t field) {
    out32(PCI_ADDRESS_PORT, io_address_for_field(addr, field));
    return in8(PCI_VALUE_PORT + (field & 3));
}

uint16_t pci_read_field16(const struct pci_addr* addr, uint8_t field) {
    out32(PCI_ADDRESS_PORT, io_address_for_field(addr, field));
    return in16(PCI_VALUE_PORT + (field & 2));
}

uint32_t pci_read_field32(const struct pci_addr* addr, uint8_t field) {
    out32(PCI_ADDRESS_PORT, io_address_for_field(addr, field));
    return in32(PCI_VALUE_PORT);
}

static void write_field16(const struct pci_addr* addr, uint8_t field,
                          uint16_t value) {
    out32(PCI_ADDRESS_PORT, io_address_for_field(addr, field));
    out16(PCI_VALUE_PORT + (field & 2), value);
}

static void write_field32(const struct pci_addr* addr, uint8_t field,
                          uint32_t value) {
    out32(PCI_ADDRESS_PORT, io_address_for_field(addr, field));
    out32(PCI_VALUE_PORT, value);
}

static void enumerate_bus(uint8_t bus, pci_device_callback_fn callback,
                          void* ctx);

static void enumerate_functions(const struct pci_addr* addr,
                                pci_device_callback_fn callback, void* ctx) {
    callback(addr, pci_read_field16(addr, PCI_VENDOR_ID),
             pci_read_field16(addr, PCI_DEVICE_ID), ctx);
    if (pci_get_type(addr) == PCI_TYPE_BRIDGE)
        enumerate_bus(pci_read_field8(addr, PCI_SECONDARY_BUS), callback, ctx);
}

static void enumerate_slot(uint8_t bus, uint8_t slot,
                           pci_device_callback_fn callback, void* ctx) {
    struct pci_addr addr = {bus, slot, 0};
    if (pci_read_field16(&addr, PCI_VENDOR_ID) == PCI_NONE)
        return;

    enumerate_functions(&addr, callback, ctx);

    if (!(pci_read_field8(&addr, PCI_HEADER_TYPE) & 0x80))
        return;

    for (addr.function = 1; addr.function < 8; ++addr.function) {
        if (pci_read_field16(&addr, PCI_VENDOR_ID) != PCI_NONE)
            enumerate_functions(&addr, callback, ctx);
    }
}

static void enumerate_bus(uint8_t bus, pci_device_callback_fn callback,
                          void* ctx) {
    for (uint8_t slot = 0; slot < 32; ++slot)
        enumerate_slot(bus, slot, callback, ctx);
}

void pci_enumerate_devices(pci_device_callback_fn callback, void* ctx) {
    struct pci_addr addr = {0};
    if ((pci_read_field8(&addr, PCI_HEADER_TYPE) & 0x80) == 0) {
        enumerate_bus(0, callback, ctx);
        return;
    }

    for (addr.function = 0; addr.function < 8; ++addr.function) {
        if (pci_read_field16(&addr, PCI_VENDOR_ID) != PCI_NONE)
            enumerate_bus(addr.function, callback, ctx);
    }
}

void pci_enumerate_capabilities(const struct pci_addr* addr,
                                pci_capability_callback_fn callback,
                                void* ctx) {
    if (!(pci_read_field16(addr, PCI_STATUS) & PCI_STATUS_CAPABILITIES_LIST))
        return;

    uint8_t pointer = pci_read_field8(addr, PCI_CAPABILITIES_POINTER);
    while (pointer) {
        uint16_t header = pci_read_field16(addr, pointer);
        uint8_t id = header & 0xff;
        callback(addr, id, pointer, ctx);
        pointer = header >> 8;
    }
}

uint16_t pci_get_type(const struct pci_addr* addr) {
    return ((uint16_t)pci_read_field8(addr, PCI_CLASS) << 8) |
           pci_read_field8(addr, PCI_SUBCLASS);
}

#define NUM_BARS 6

const uint8_t bar_fields[NUM_BARS] = {PCI_BAR0, PCI_BAR1, PCI_BAR2,
                                      PCI_BAR3, PCI_BAR4, PCI_BAR5};

uint32_t pci_get_bar(const struct pci_addr* addr, uint8_t bar) {
    ASSERT(bar < NUM_BARS);
    return pci_read_field32(addr, bar_fields[bar]);
}

static void write_bar(const struct pci_addr* addr, uint8_t bar,
                      uint32_t value) {
    ASSERT(bar < NUM_BARS);
    write_field32(addr, bar_fields[bar], value);
}

void* pci_map_bar(const struct pci_addr* pci_addr, uint8_t bar) {
    uint32_t bar_value = pci_get_bar(pci_addr, bar);
    if ((bar_value & PCI_BAR_SPACE) == PCI_BAR_SPACE_IO)
        return ERR_PTR(-EINVAL);

    if (((bar_value >> 1) & 3) == 2) {
        // Base address is 64-bit. 64-bit base address spans two BARs.
        if (bar >= NUM_BARS - 1)
            return ERR_PTR(-EINVAL);
        if (pci_get_bar(pci_addr, bar + 1) != 0) {
            // TODO: Support 64-bit base address
            return ERR_PTR(-EINVAL);
        }
    }

    phys_addr_t phys_addr = bar_value & ~0xf;

    write_bar(pci_addr, bar, 0xffffffff);
    uint32_t size = pci_get_bar(pci_addr, bar);
    write_bar(pci_addr, bar, bar_value);
    size &= ~0xf;
    size = (~size) + 1;

    return phys_map(phys_addr, size, VM_READ | VM_WRITE);
}

uint8_t pci_get_interrupt_line(const struct pci_addr* addr) {
    return pci_read_field8(addr, PCI_INTERRUPT_LINE);
}

void pci_set_interrupt_line_enabled(const struct pci_addr* addr, bool enabled) {
    uint16_t command = pci_read_field16(addr, PCI_COMMAND);
    if (enabled)
        command &= ~PCI_COMMAND_INTERRUPT_DISABLE;
    else
        command |= PCI_COMMAND_INTERRUPT_DISABLE;
    write_field16(addr, PCI_COMMAND, command);
}

void pci_set_bus_mastering_enabled(const struct pci_addr* addr, bool enabled) {
    uint16_t command = pci_read_field16(addr, PCI_COMMAND);
    if (enabled)
        command |= PCI_COMMAND_BUS_MASTER;
    else
        command &= ~PCI_COMMAND_BUS_MASTER;
    command |= PCI_COMMAND_IO_SPACE;
    write_field16(addr, PCI_COMMAND, command);
}
