#include "virtio_pci.h"
#include "virtio_queue.h"
#include <common/extra.h>
#include <stddef.h>

struct pci_addr;

struct virtio_device {
    void* notify_space;
    size_t num_virtqs;
    struct virtq* virtqs[];
};

struct virtio_device* virtio_device_create(const struct pci_addr*,
                                           size_t num_virtqs);
void virtio_device_destroy(struct virtio_device*);

NODISCARD bool virtio_find_pci_cap(const struct pci_addr*, uint8_t cfg_type,
                                   struct virtio_pci_cap* out_cap);
