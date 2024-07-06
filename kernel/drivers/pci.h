#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PCI_BAR_SPACE 0x1
#define PCI_BAR_SPACE_IO 0x1

#define PCI_CAP_ID_VNDR 0x09

struct pci_addr {
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
};

typedef void (*pci_device_callback_fn)(const struct pci_addr*,
                                       uint16_t vendor_id, uint16_t device_id,
                                       void* ctx);
void pci_enumerate_devices(pci_device_callback_fn, void* ctx);

typedef void (*pci_capability_callback_fn)(const struct pci_addr*, uint8_t id,
                                           uint8_t pointer, void* ctx);
void pci_enumerate_capabilities(const struct pci_addr*,
                                pci_capability_callback_fn, void* ctx);

uint8_t pci_read_field8(const struct pci_addr*, uint8_t field);
uint16_t pci_read_field16(const struct pci_addr*, uint8_t field);
uint32_t pci_read_field32(const struct pci_addr*, uint8_t field);

uint16_t pci_get_type(const struct pci_addr*);

uint32_t pci_get_bar(const struct pci_addr*, uint8_t bar);
void* pci_map_bar(const struct pci_addr*, uint8_t bar);

uint8_t pci_get_interrupt_line(const struct pci_addr*);
void pci_set_interrupt_line_enabled(const struct pci_addr*, bool enabled);
void pci_set_bus_mastering_enabled(const struct pci_addr*, bool enabled);
