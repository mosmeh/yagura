#include <common/stddef.h>
#include <kernel/drivers/pci.h>
#include <kernel/drivers/virtio/virtio_pci.h>
#include <kernel/drivers/virtio/virtio_queue.h>
#include <kernel/resource.h>

struct virtio {
    struct pci_addr addr;
    uint8_t irq;
    void* notify_space;
    volatile uint16_t* notify;
    void* isr_space;
    volatile uint8_t* isr;
    size_t num_virtqs;
    struct virtq* virtqs[];
};

struct virtio* virtio_create(const struct pci_addr*, size_t num_virtqs);
void virtio_destroy(struct virtio*);

DEFINE_FREE(virtio, struct virtio, virtio_destroy)

NODISCARD bool virtio_find_pci_cap(const struct pci_addr*, uint8_t cfg_type,
                                   struct virtio_pci_cap* out_cap);
