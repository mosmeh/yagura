#pragma once

#include <stdint.h>

typedef void (*pci_enumeration_callback_fn)(uint8_t bus, uint8_t slot,
                                            uint8_t function,
                                            uint16_t vendor_id,
                                            uint16_t device_id);

void pci_enumerate(pci_enumeration_callback_fn callback);
uint32_t pci_get_bar0(uint8_t bus, uint8_t slot, uint8_t function);
