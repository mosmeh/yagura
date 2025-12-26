#include <common/stdio.h>
#include <common/string.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/device.h>
#include <kernel/drivers/pci.h>
#include <kernel/drivers/virtio/virtio.h>
#include <kernel/drivers/virtio/virtio_blk.h>
#include <kernel/kmsg.h>
#include <kernel/panic.h>
#include <kernel/sched.h>

struct virtio_blk {
    struct block_dev block_dev;
    struct virtio* virtio;
};

static struct virtio_blk* blk_from_block_dev(struct block_dev* block_dev) {
    return CONTAINER_OF(block_dev, struct virtio_blk, block_dev);
}

struct unblock_ctx {
    struct virtq* virtq;
    size_t num_descriptors;
};

static bool unblock_request(void* raw_ctx) {
    struct unblock_ctx* ctx = raw_ctx;
    return ctx->virtq->num_free_descs >= ctx->num_descriptors;
}

static int submit_request(struct block_dev* block_dev, void* buffer,
                          uint64_t sector, uint64_t nsectors, uint32_t type,
                          bool device_writable) {
    struct virtio_blk* blk = blk_from_block_dev(block_dev);
    struct virtq* virtq = blk->virtio->virtqs[0];
    struct virtio_blk_req_header header = {
        .type = type,
        .sector = sector,
    };
    uint64_t count = nsectors << block_dev->block_bits;
    struct virtio_blk_req_footer footer = {0};

    size_t num_descriptors = 2;
    if (buffer)
        ++num_descriptors;
    struct unblock_ctx unblock_ctx = {
        .virtq = blk->virtio->virtqs[0],
        .num_descriptors = num_descriptors,
    };

    for (;;) {
        int rc =
            sched_block(unblock_request, &unblock_ctx, BLOCK_UNINTERRUPTIBLE);
        if (IS_ERR(rc))
            return rc;

        SCOPED_LOCK(block_dev, block_dev);

        struct virtq_desc_chain chain;
        if (!virtq_desc_chain_init(&chain, virtq, num_descriptors))
            continue;
        virtq_desc_chain_push_buf(&chain, &header, sizeof(header), false);
        if (buffer)
            virtq_desc_chain_push_buf(&chain, buffer, count, device_writable);
        virtq_desc_chain_push_buf(&chain, &footer, sizeof(footer), true);
        rc = virtq_desc_chain_submit(&chain);
        if (IS_ERR(rc))
            return rc;
        break;
    }

    switch (footer.status) {
    case VIRTIO_BLK_S_OK:
        return 0;
    case VIRTIO_BLK_S_UNSUPP:
        return -ENOTSUP;
    default:
        return -EIO;
    }
}

static ssize_t virtio_blk_read(struct block_dev* block_dev, void* buffer,
                               uint64_t index, uint64_t nblocks) {
    return submit_request(block_dev, buffer, index, nblocks, VIRTIO_BLK_T_IN,
                          true);
}

static ssize_t virtio_blk_write(struct block_dev* block_dev, const void* buffer,
                                uint64_t index, uint64_t nblocks) {
    return submit_request(block_dev, (void*)buffer, index, nblocks,
                          VIRTIO_BLK_T_OUT, false);
}

static int virtio_blk_flush(struct block_dev* block_dev) {
    return submit_request(block_dev, NULL, 1, 0, VIRTIO_BLK_T_FLUSH, false);
}

static void init_device(const struct pci_addr* addr) {
    struct virtio_pci_cap device_cfg_cap;
    if (!virtio_find_pci_cap(addr, VIRTIO_PCI_CAP_DEVICE_CFG,
                             &device_cfg_cap)) {
        kprint("virtio_blk: device is missing VIRTIO_PCI_CAP_DEVICE_CFG\n");
        return;
    }

    static size_t next_id = 0;
    if (next_id > 255) {
        kprint("virtio_blk: too many devices\n");
        return;
    }

    struct virtio* virtio FREE(virtio) = virtio_create(addr, 1);
    if (IS_ERR(ASSERT(virtio))) {
        kprint("virtio_blk: failed to initialize a virtio device\n");
        return;
    }

    unsigned char* device_cfg_space = pci_map_bar(addr, device_cfg_cap.bar);
    if (IS_ERR(ASSERT(device_cfg_space))) {
        kprint("virtio_blk: failed to map device config space\n");
        return;
    }
    volatile struct virtio_blk_config* blk_config =
        (volatile struct virtio_blk_config*)(device_cfg_space +
                                             device_cfg_cap.offset);
    uint64_t capacity = blk_config->capacity;
    phys_unmap(device_cfg_space);

    struct virtio_blk* blk = kmalloc(sizeof(struct virtio_blk));
    if (!blk) {
        kprint("virtio_blk: failed to allocate virtio_blk\n");
        return;
    }
    *blk = (struct virtio_blk){
        .block_dev = BLOCK_DEV_INIT,
        .virtio = TAKE_PTR(virtio),
    };

    size_t id = next_id++;
    char name[8] = "vd";
    if (id < 26) {
        name[2] = 'a' + id;
    } else {
        name[2] = 'a' + id / 26 - 1;
        name[3] = 'a' + id % 26;
    }

    static const struct block_ops bops = {
        .read = virtio_blk_read,
        .write = virtio_blk_write,
        .flush = virtio_blk_flush,
    };

    struct block_dev* block_dev = &blk->block_dev;
    strlcpy(block_dev->name, name, sizeof(block_dev->name));
    block_dev->dev = makedev(254, id);
    block_dev->bops = &bops;
    block_dev->block_bits = SECTOR_SHIFT;
    block_dev->num_blocks = capacity;

    ASSERT_OK(block_dev_register(block_dev));
    block_dev_unref(block_dev);
}

static void pci_device_callback(const struct pci_addr* addr, uint16_t vendor_id,
                                uint16_t device_id, void* ctx) {
    (void)ctx;
    if (vendor_id == 0x1af4 && device_id == 0x1001)
        init_device(addr);
}

void virtio_blk_init(void) { pci_enumerate_devices(pci_device_callback, NULL); }
