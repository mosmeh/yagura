#pragma once

#include <stdint.h>

struct pci_addr {
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
};

typedef void (*pci_enumeration_callback_fn)(const struct pci_addr*,
                                            uint16_t vendor_id,
                                            uint16_t device_id);

void pci_enumerate(pci_enumeration_callback_fn);
uint32_t pci_get_bar0(const struct pci_addr*);
