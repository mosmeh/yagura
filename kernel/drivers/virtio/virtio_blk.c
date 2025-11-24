#include "virtio_blk.h"
#include "virtio.h"
#include <common/stdio.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/device/device.h>
#include <kernel/drivers/pci.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/sched.h>

struct virtio_blk {
    struct inode vfs_inode;
    struct virtio_device* virtio;
    uint64_t capacity;
};

static struct virtio_blk* blk_from_inode(struct inode* inode) {
    return CONTAINER_OF(inode, struct virtio_blk, vfs_inode);
}

static void virtio_blk_destroy(struct inode* inode) {
    struct virtio_blk* blk = blk_from_inode(inode);
    virtio_device_destroy(blk->virtio);
    kfree(blk);
}

static bool unblock_request(struct file* file) {
    struct virtio_blk* blk = blk_from_inode(file->inode);
    return blk->virtio->virtqs[0]->num_free_descs >= 3;
}

static int submit_request(struct file* file, void* buffer, size_t count,
                          uint64_t sector, uint32_t type,
                          bool device_writable) {
    struct virtio_blk* blk = blk_from_inode(file->inode);
    struct virtq* virtq = blk->virtio->virtqs[0];
    struct virtio_blk_req_header header = {
        .type = type,
        .sector = sector,
    };
    struct virtio_blk_req_footer footer = {0};

    int rc;
retry:
    rc = file_block(file, unblock_request, BLOCK_UNINTERRUPTIBLE);
    if (IS_ERR(rc))
        return rc;

    mutex_lock(&file->inode->lock);
    struct virtq_desc_chain chain;
    if (!virtq_desc_chain_init(&chain, virtq, 3)) {
        mutex_unlock(&file->inode->lock);
        goto retry;
    }
    virtq_desc_chain_push_buf(&chain, &header, sizeof(header), false);
    virtq_desc_chain_push_buf(&chain, buffer, count, device_writable);
    virtq_desc_chain_push_buf(&chain, &footer, sizeof(footer), true);
    rc = virtq_desc_chain_submit(&chain);
    mutex_unlock(&file->inode->lock);
    if (IS_ERR(rc))
        return rc;

    switch (footer.status) {
    case VIRTIO_BLK_S_OK:
        return 0;
    case VIRTIO_BLK_S_UNSUPP:
        return -ENOTSUP;
    default:
        return -EIO;
    }
}

static ssize_t virtio_blk_do_io(struct file* file, void* buffer, size_t count,
                                uint64_t offset, uint32_t type,
                                bool device_writable) {
    if (count % SECTOR_SIZE != 0)
        return -EINVAL;

    if (offset % SECTOR_SIZE != 0)
        return -EINVAL;
    uint64_t sector = offset >> SECTOR_SHIFT;

    struct virtio_blk* blk = blk_from_inode(file->inode);
    if (sector >= blk->capacity)
        return 0;
    count = MIN(count, (blk->capacity - sector) << SECTOR_SHIFT);

    int rc = submit_request(file, buffer, count, sector, type, device_writable);
    if (IS_ERR(rc))
        return rc;

    return count;
}

static ssize_t virtio_blk_pread(struct file* file, void* buffer, size_t count,
                                uint64_t offset) {
    return virtio_blk_do_io(file, buffer, count, offset, VIRTIO_BLK_T_IN, true);
}

static ssize_t virtio_blk_pwrite(struct file* file, const void* buffer,
                                 size_t count, uint64_t offset) {
    return virtio_blk_do_io(file, (void*)buffer, count, offset,
                            VIRTIO_BLK_T_OUT, false);
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

    struct virtio_device* virtio = virtio_device_create(addr, 1);
    if (IS_ERR(virtio)) {
        kprint("virtio_blk: failed to initialize a virtio device\n");
        return;
    }

    struct block_dev* block_dev = NULL;

    unsigned char* device_cfg_space = pci_map_bar(addr, device_cfg_cap.bar);
    if (IS_ERR(device_cfg_space))
        goto fail;
    volatile struct virtio_blk_config* blk_config =
        (volatile struct virtio_blk_config*)(device_cfg_space +
                                             device_cfg_cap.offset);
    uint64_t capacity = blk_config->capacity;
    phys_unmap(device_cfg_space);

    size_t id = next_id++;
    block_dev = kmalloc(sizeof(struct block_dev));
    if (!block_dev)
        goto fail;
    *block_dev = (struct block_dev){
        .name = "vd",
    };
    if (id < 26) {
        block_dev->name[2] = 'a' + id;
    } else {
        block_dev->name[2] = 'a' + id / 26 - 1;
        block_dev->name[3] = 'a' + id % 26;
    }

    struct virtio_blk* blk = kmalloc(sizeof(struct virtio_blk));
    if (!blk)
        goto fail;
    *blk = (struct virtio_blk){
        .vfs_inode = INODE_INIT,
        .virtio = virtio,
        .capacity = capacity,
    };

    struct inode* inode = &blk->vfs_inode;
    block_dev->inode = inode;
    static const struct inode_ops iops = {
        .destroy = virtio_blk_destroy,
    };
    static const struct file_ops fops = {
        .pread = virtio_blk_pread,
        .pwrite = virtio_blk_pwrite,
    };
    inode->iops = &iops;
    inode->fops = &fops;
    inode->mode = S_IFBLK;
    inode->rdev = makedev(254, id);
    inode->size = capacity << SECTOR_SHIFT;
    inode->block_bits = SECTOR_SHIFT;
    inode->blocks = capacity;

    ASSERT_OK(block_dev_register(block_dev));
    return;

fail:
    kfree(block_dev);
    virtio_device_destroy(virtio);
}

static void pci_device_callback(const struct pci_addr* addr, uint16_t vendor_id,
                                uint16_t device_id, void* ctx) {
    (void)ctx;
    if (vendor_id == 0x1af4 && device_id == 0x1001)
        init_device(addr);
}

void virtio_blk_init(void) { pci_enumerate_devices(pci_device_callback, NULL); }
