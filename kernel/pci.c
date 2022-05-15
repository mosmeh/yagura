#include "pci.h"
#include "asm_wrapper.h"

#define PCI_VENDOR_ID 0x0
#define PCI_DEVICE_ID 0x2
#define PCI_SUBCLASS 0xa
#define PCI_CLASS 0xb
#define PCI_HEADER_TYPE 0xe
#define PCI_BAR0 0x10
#define PCI_SECONDARY_BUS 0x19
#define PCI_ADDRESS_PORT 0xcf8
#define PCI_TYPE_BRIDGE 0x604
#define PCI_VALUE_PORT 0xcfc
#define PCI_NONE 0xffff

static uint32_t io_address_for_field(const struct pci_addr* addr,
                                     uint8_t field) {
    return 0x80000000 | ((uint32_t)addr->bus << 16) |
           ((uint32_t)addr->slot << 11) | ((uint32_t)addr->function << 8) |
           (field & 0xfc);
}

static uint16_t read_field8(const struct pci_addr* addr, uint8_t field) {
    out32(PCI_ADDRESS_PORT, io_address_for_field(addr, field));
    return in8(PCI_VALUE_PORT + (field & 3));
}

static uint16_t read_field16(const struct pci_addr* addr, uint8_t field) {
    out32(PCI_ADDRESS_PORT, io_address_for_field(addr, field));
    return in16(PCI_VALUE_PORT + (field & 2));
}

static uint32_t read_field32(const struct pci_addr* addr, uint8_t field) {
    out32(PCI_ADDRESS_PORT, io_address_for_field(addr, field));
    return in32(PCI_VALUE_PORT);
}

static uint16_t read_type(const struct pci_addr* addr) {
    return ((uint16_t)read_field8(addr, PCI_CLASS) << 8) |
           read_field8(addr, PCI_SUBCLASS);
}

static void enumerate_bus(uint8_t bus, pci_enumeration_callback_fn callback);

static void enumerate_functions(const struct pci_addr* addr,
                                pci_enumeration_callback_fn callback) {
    callback(addr, read_field16(addr, PCI_VENDOR_ID),
             read_field16(addr, PCI_DEVICE_ID));
    if (read_type(addr) == PCI_TYPE_BRIDGE)
        enumerate_bus(read_field8(addr, PCI_SECONDARY_BUS), callback);
}

static void enumerate_slot(uint8_t bus, uint8_t slot,
                           pci_enumeration_callback_fn callback) {
    struct pci_addr addr = {bus, slot, 0};
    if (read_field16(&addr, PCI_VENDOR_ID) == PCI_NONE)
        return;

    enumerate_functions(&addr, callback);

    if (!(read_field8(&addr, PCI_HEADER_TYPE) & 0x80))
        return;

    for (addr.function = 1; addr.function < 8; ++addr.function) {
        if (read_field16(&addr, PCI_VENDOR_ID) != PCI_NONE)
            enumerate_functions(&addr, callback);
    }
}

static void enumerate_bus(uint8_t bus, pci_enumeration_callback_fn callback) {
    for (uint8_t slot = 0; slot < 32; ++slot)
        enumerate_slot(bus, slot, callback);
}

void pci_enumerate(pci_enumeration_callback_fn callback) {
    struct pci_addr addr = {0};
    if ((read_field8(&addr, PCI_HEADER_TYPE) & 0x80) == 0) {
        enumerate_bus(0, callback);
        return;
    }

    for (addr.function = 0; addr.function < 8; ++addr.function) {
        if (read_field16(&addr, PCI_VENDOR_ID) != PCI_NONE)
            enumerate_bus(addr.function, callback);
    }
}

uint32_t pci_get_bar0(const struct pci_addr* addr) {
    return read_field32(addr, PCI_BAR0);
}
