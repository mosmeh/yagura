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

static uint32_t io_address_for_field(uint8_t bus, uint8_t slot,
                                     uint8_t function, uint8_t field) {
    return 0x80000000 | ((uint32_t)bus << 16) | ((uint32_t)slot << 11) |
           ((uint32_t)function << 8) | (field & 0xfc);
}

static uint16_t read_field8(uint8_t bus, uint8_t slot, uint8_t function,
                            uint8_t field) {
    out32(PCI_ADDRESS_PORT, io_address_for_field(bus, slot, function, field));
    return in8(PCI_VALUE_PORT + (field & 3));
}

static uint16_t read_field16(uint8_t bus, uint8_t slot, uint8_t function,
                             uint8_t field) {
    out32(PCI_ADDRESS_PORT, io_address_for_field(bus, slot, function, field));
    return in16(PCI_VALUE_PORT + (field & 2));
}

static uint32_t read_field32(uint8_t bus, uint8_t slot, uint8_t function,
                             uint8_t field) {
    out32(PCI_ADDRESS_PORT, io_address_for_field(bus, slot, function, field));
    return in32(PCI_VALUE_PORT);
}

static uint16_t read_type(uint8_t bus, uint8_t slot, uint8_t function) {
    return ((uint16_t)read_field8(bus, slot, function, PCI_CLASS) << 8) |
           read_field8(bus, slot, function, PCI_SUBCLASS);
}

static void enumerate_bus(uint8_t bus, pci_enumeration_callback_fn callback);

static void enumerate_functions(uint8_t bus, uint8_t slot, uint8_t function,
                                pci_enumeration_callback_fn callback) {
    callback(bus, slot, function,
             read_field16(bus, slot, function, PCI_VENDOR_ID),
             read_field16(bus, slot, function, PCI_DEVICE_ID));
    if (read_type(bus, slot, function) == PCI_TYPE_BRIDGE)
        enumerate_bus(read_field8(bus, slot, function, PCI_SECONDARY_BUS),
                      callback);
}

static void enumerate_slot(uint8_t bus, uint8_t slot,
                           pci_enumeration_callback_fn callback) {
    if (read_field16(bus, slot, 0, PCI_VENDOR_ID) == PCI_NONE)
        return;

    enumerate_functions(bus, slot, 0, callback);

    if (!(read_field8(bus, slot, 0, PCI_HEADER_TYPE) & 0x80))
        return;

    for (uint8_t function = 1; function < 8; ++function) {
        if (read_field16(bus, slot, function, PCI_VENDOR_ID) != PCI_NONE)
            enumerate_functions(bus, slot, function, callback);
    }
}

static void enumerate_bus(uint8_t bus, pci_enumeration_callback_fn callback) {
    for (uint8_t slot = 0; slot < 32; ++slot)
        enumerate_slot(bus, slot, callback);
}

void pci_enumerate(pci_enumeration_callback_fn callback) {
    if ((read_field8(0, 0, 0, PCI_HEADER_TYPE) & 0x80) == 0) {
        enumerate_bus(0, callback);
        return;
    }

    for (uint8_t function = 0; function < 8; ++function) {
        if (read_field16(0, 0, function, PCI_VENDOR_ID) != PCI_NONE)
            enumerate_bus(function, callback);
    }
}

uint32_t pci_get_bar0(uint8_t bus, uint8_t slot, uint8_t function) {
    return read_field32(bus, slot, function, PCI_BAR0);
}
