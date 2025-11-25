#include "virtio.h"
#include "virtio_config.h"
#include "virtio_pci.h"
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/drivers/pci.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/vm.h>
#include <kernel/panic.h>
#include <kernel/sched.h>
#include <kernel/system.h>

// virtio spec: https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html

static struct virtq* virtq_create(uint16_t queue_size) {
    // 2.7 Split Virtqueues
#define DESC_ALIGN 16
#define AVAIL_ALIGN 2
#define USED_ALIGN 4
    size_t desc_size = sizeof(struct virtq_desc) * queue_size;
    size_t avail_size =
        sizeof(struct virtq_avail) + sizeof(uint16_t) * queue_size;
    size_t used_size =
        sizeof(struct virtq_used) + sizeof(struct virtq_used_elem) * queue_size;

    size_t alloc_size = ROUND_UP(sizeof(struct virtq), DESC_ALIGN);
    alloc_size = ROUND_UP(alloc_size + desc_size, AVAIL_ALIGN);
    alloc_size = ROUND_UP(alloc_size + avail_size, USED_ALIGN);
    alloc_size += used_size;

    struct virtq* virtq = kaligned_alloc(DESC_ALIGN, alloc_size);
    if (!virtq)
        return NULL;
    memset(virtq, 0, alloc_size);

    virtq->size = queue_size;
    virtq->num_free_descs = queue_size;

    uintptr_t ptr =
        ROUND_UP((uintptr_t)virtq + sizeof(struct virtq), DESC_ALIGN);
    ASSERT(ptr % DESC_ALIGN == 0);
    virtq->desc = (struct virtq_desc*)ptr;

    ptr = ROUND_UP(ptr + desc_size, AVAIL_ALIGN);
    ASSERT(ptr % AVAIL_ALIGN == 0);
    virtq->avail = (struct virtq_avail*)ptr;

    ptr = ROUND_UP(ptr + avail_size, USED_ALIGN);
    ASSERT(ptr % USED_ALIGN == 0);
    virtq->used = (struct virtq_used*)ptr;

    for (uint16_t i = 0; i + 1 < queue_size; ++i) {
        // Chain all the descriptors.
        virtq->desc[i].next = i + 1;
    }

    // virtq_wait_completion uses polling, not interrupts.
    virtq->avail->flags = VIRTQ_AVAIL_F_NO_INTERRUPT;

    return virtq;
}

bool virtq_is_ready(const struct virtq* virtq) {
    return virtq->used->idx == virtq->avail_index_shadow;
}

bool virtq_desc_chain_init(struct virtq_desc_chain* chain, struct virtq* virtq,
                           size_t num_descriptors) {
    if (virtq->num_free_descs < num_descriptors)
        return false;
    chain->virtq = virtq;
    chain->num_pushed = 0;
    return true;
}

void virtq_desc_chain_push_buf(struct virtq_desc_chain* chain, void* buf,
                               size_t len, bool device_writable) {
    struct virtq* virtq = chain->virtq;
    ASSERT(virtq->num_free_descs > 0);

    // 2.7.13.1 Placing Buffers Into The Descriptor Table

    // 1. Get the next free descriptor table entry, d
    size_t head = virtq->free_head;
    struct virtq_desc* d = &virtq->desc[head];

    // 2. Set d.addr to the physical address of the start of b
    d->addr = virt_to_phys(buf);

    // 3. Set d.len to the length of b.
    d->len = len;

    // 4. If b is device-writable, set d.flags to VIRTQ_DESC_F_WRITE, otherwise
    //    0.
    d->flags = device_writable ? VIRTQ_DESC_F_WRITE : 0;

    // 5. If there is a buffer element after this:
    if (chain->num_pushed) {
        struct virtq_desc* prev = &virtq->desc[chain->tail];
        // (a) Set d.next to the index of the next free descriptor element.
        prev->next = head;
        // (b) Set the VIRTQ_DESC_F_NEXT bit in d.flags.
        prev->flags |= VIRTQ_DESC_F_NEXT;
    } else {
        chain->head = head;
    }
    chain->tail = head;

    // In practice, d.next is usually used to chain free
    // descriptors, and a separate count kept to check there are enough free
    // descriptors before beginning the mappings.
    virtq->free_head = d->next;
    --virtq->num_free_descs;
    ++chain->num_pushed;
}

int virtq_desc_chain_submit(struct virtq_desc_chain* chain) {
    if (chain->num_pushed == 0)
        return 0;

    struct virtq* virtq = chain->virtq;

    // 2.7.13 Supplying Buffers to The Device

    // 1. The driver places the buffer into free descriptor(s) in the descriptor
    //    table, chaining as necessary.
    // (done in virtq_chain_append_buf)

    // 2. The driver places the index of the head of the descriptor chain into
    //    the next ring entry of the available ring.
    uint16_t next_index = virtq->avail_index_shadow % virtq->size;
    virtq->avail->ring[next_index] = chain->head;
    ++virtq->avail_index_shadow;

    // 3. Steps 1 and 2 MAY be performed repeatedly if batching is possible.
    // (we don't submit multiple chains at once)

    // 4. The driver performs a suitable memory barrier to ensure the device
    //    sees the updated descriptor table and available ring before the next
    //    step.
    full_memory_barrier();

    // 5. The available idx is increased by the number of descriptor chain
    //    heads added to the available ring.
    virtq->avail->idx = virtq->avail_index_shadow;

    // 6. The driver performs a suitable memory barrier to ensure that it
    //    updates the idx field before checking for notification suppression.
    full_memory_barrier();

    // 7. The driver sends an available buffer notification to the device if
    //    such notifications are not suppressed.
    if (!(virtq->used->flags & VIRTQ_USED_F_NO_NOTIFY))
        *virtq->notify = virtq->index;

    int rc =
        sched_block((unblock_fn)virtq_is_ready, virtq, BLOCK_UNINTERRUPTIBLE);
    full_memory_barrier();

    // Return the descriptors to the free list.
    virtq->desc[chain->tail].next = virtq->free_head;
    virtq->free_head = chain->head;
    virtq->num_free_descs += chain->num_pushed;

    // Reset the chain.
    chain->num_pushed = 0;

    return rc;
}

static struct virtio_pci_cap read_cap(const struct pci_addr* addr,
                                      uint8_t pointer) {
    return (struct virtio_pci_cap){
        .cap_vndr = pci_read_field8(addr, pointer + 0x0),
        .cap_next = pci_read_field8(addr, pointer + 0x1),
        .cap_len = pci_read_field8(addr, pointer + 0x2),
        .cfg_type = pci_read_field8(addr, pointer + 0x3),
        .bar = pci_read_field8(addr, pointer + 0x4),
        .id = pci_read_field8(addr, pointer + 0x5),
        .offset = pci_read_field32(addr, pointer + 0x8),
        .length = pci_read_field32(addr, pointer + 0xc),
    };
}

struct capability_enumeration_context {
    uint8_t cfg_type;
    struct virtio_pci_cap cap;
    bool found;
};

static void
pci_capability_callback(const struct pci_addr* addr, uint8_t id,
                        uint8_t pointer,
                        struct capability_enumeration_context* ctx) {
    if (id != PCI_CAP_ID_VNDR)
        return;
    struct virtio_pci_cap cap = read_cap(addr, pointer);
    if (cap.cfg_type != ctx->cfg_type)
        return;
    ctx->found = true;
    ctx->cap = cap;
}

bool virtio_find_pci_cap(const struct pci_addr* addr, uint8_t cfg_type,
                         struct virtio_pci_cap* out_cap) {
    struct capability_enumeration_context ctx = {
        .cfg_type = cfg_type,
        .found = false,
    };
    pci_enumerate_capabilities(
        addr, (pci_capability_callback_fn)pci_capability_callback, &ctx);
    if (!ctx.found)
        return false;
    if (out_cap)
        *out_cap = ctx.cap;
    return true;
}

struct virtio* virtio_create(const struct pci_addr* addr, size_t num_virtqs) {
    struct virtio_pci_cap common_cfg_cap;
    if (!virtio_find_pci_cap(addr, VIRTIO_PCI_CAP_COMMON_CFG,
                             &common_cfg_cap)) {
        kprint("virtio: device is missing VIRTIO_PCI_CAP_COMMON_CFG\n");
        return false;
    }

    struct virtio* virtio =
        kmalloc(sizeof(struct virtio) + num_virtqs * sizeof(struct virtq*));
    if (!virtio)
        return ERR_PTR(-ENOMEM);
    *virtio = (struct virtio){
        .num_virtqs = num_virtqs,
    };

    int ret = 0;

    unsigned char* common_cfg_space = pci_map_bar(addr, common_cfg_cap.bar);
    if (IS_ERR(common_cfg_space))
        goto fail_discovery;
    volatile struct virtio_pci_common_cfg* common_cfg =
        (volatile struct virtio_pci_common_cfg*)(common_cfg_space +
                                                 common_cfg_cap.offset);

    struct virtio_pci_notify_cap notify_cap = {0};
    if (!virtio_find_pci_cap(addr, VIRTIO_PCI_CAP_NOTIFY_CFG,
                             &notify_cap.cap)) {
        kprint("virtio: device is missing VIRTIO_PCI_CAP_NOTIFY_CFG\n");
        goto fail_discovery;
    }

    uintptr_t notify_offset =
        notify_cap.cap.offset +
        common_cfg->queue_notify_off * notify_cap.notify_off_multiplier;
    unsigned char* notify_space = pci_map_bar(addr, notify_cap.cap.bar);
    if (IS_ERR(notify_space))
        goto fail_discovery;

    virtio->notify_space = notify_space;
    uint16_t* notify = (uint16_t*)(notify_space + notify_offset);

    // 3.1.1 Driver Requirements: Device Initialization

    // 1. Reset the device.
    common_cfg->device_status = 0;
    while (common_cfg->device_status)
        ;

    // 2. Set the ACKNOWLEDGE status bit: the guest OS has noticed the device.
    common_cfg->device_status |= VIRTIO_CONFIG_S_ACKNOWLEDGE;

    // 3. Set the DRIVER status bit: the guest OS knows how to drive the device.
    common_cfg->device_status |= VIRTIO_CONFIG_S_DRIVER;

    // 4. Read device feature bits, and write the subset of feature bits
    //    understood by the OS and driver to the device. During this step the
    //    driver MAY read (but MUST NOT write) the device-specific configuration
    //    fields to check that it can support the device before accepting it.
    // We don't support any features.
    common_cfg->driver_feature_select = 0;
    common_cfg->driver_feature = 0;
    common_cfg->driver_feature_select = 1;
    common_cfg->driver_feature = 0;

    // 5. Set the FEATURES_OK status bit. The driver MUST NOT accept new feature
    //    bits after this step.
    common_cfg->device_status |= VIRTIO_CONFIG_S_FEATURES_OK;

    // 6. Re-read device status to ensure the FEATURES_OK bit is still set:
    //    otherwise, the device does not support our subset of features and the
    //    device is unusable.
    if (!(common_cfg->device_status & VIRTIO_CONFIG_S_FEATURES_OK)) {
        kprint("virtio: failed to negotiate features\n");
        goto fail_initialization;
    }

    // 7. Perform device-specific setup, including discovery of virtqueues for
    //    the device, optional per-bus setup, reading and possibly writing the
    //    device’s virtio configuration space, and population of virtqueues.
    uint16_t max_num_queues = common_cfg->num_queues;
    if (num_virtqs > max_num_queues) {
        kprintf("virtio: requested %u virtqueues, but only %u are available\n",
                num_virtqs, max_num_queues);
        goto fail_initialization;
    }

    for (size_t i = 0; i < num_virtqs; ++i) {
        common_cfg->queue_select = i;

        uint16_t queue_size = common_cfg->queue_size;
        if (queue_size == 0) {
            kprintf("virtio: queue %u is not available\n", i);
            goto fail_initialization;
        }

        struct virtq* virtq = virtq_create(queue_size);
        if (!virtq)
            goto fail_initialization;
        virtq->index = i;
        virtq->notify = notify;

        common_cfg->queue_desc = virt_to_phys(virtq->desc);
        common_cfg->queue_driver = virt_to_phys(virtq->avail);
        common_cfg->queue_device = virt_to_phys((void*)virtq->used);

        common_cfg->queue_enable = 1;

        virtio->virtqs[i] = virtq;
    }

    // 8. Set the DRIVER_OK status bit. At this point the device is “live”. If
    //    any of these steps go irrecoverably wrong, the driver SHOULD set the
    //    FAILED status bit to indicate that it has given up on the device (it
    //    can reset the device later to restart if desired). The driver MUST NOT
    //    continue initialization in that case.
    common_cfg->device_status |= VIRTIO_CONFIG_S_DRIVER_OK;

    return virtio;

fail_initialization:
    common_cfg->device_status |= VIRTIO_CONFIG_S_FAILED;
fail_discovery:
    phys_unmap(common_cfg_space);
    virtio_destroy(virtio);
    return ERR_PTR(ret);
}

void virtio_destroy(struct virtio* virtio) {
    if (!virtio)
        return;
    for (size_t i = 0; i < virtio->num_virtqs; ++i) {
        struct virtq* virtq = virtio->virtqs[i];
        if (virtq) {
            kfree(virtq);
            virtio->virtqs[i] = NULL;
        }
    }
    phys_unmap(virtio->notify_space);
    kfree(virtio);
}
