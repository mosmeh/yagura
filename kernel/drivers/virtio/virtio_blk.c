#include "virtio_blk.h"
#include "virtio.h"
#include <common/stdio.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/drivers/pci.h>
#include <kernel/fs/fs.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>

#define SECTOR_SIZE 512

typedef struct virtio_blk_device {
    struct inode inode;
    mutex lock;
    struct virtio_device* virtio;
    uint64_t capacity;
} virtio_blk_device;

static void virtio_blk_destroy_inode(struct inode* inode) {
    virtio_blk_device* node = (virtio_blk_device*)inode;
    virtio_device_destroy(node->virtio);
    kfree(node);
}

static bool unblock_request(file_description* desc) {
    virtio_blk_device* node = (virtio_blk_device*)desc->inode;
    return node->virtio->virtqs[0]->num_free_descs >= 3;
}

static int submit_request(file_description* desc, void* buffer, size_t count,
                          uint64_t sector, uint32_t type,
                          bool device_writable) {
    virtio_blk_device* node = (virtio_blk_device*)desc->inode;
    struct virtq* virtq = node->virtio->virtqs[0];
    struct virtio_blk_req_header header = {
        .type = type,
        .sector = sector,
    };
    struct virtio_blk_req_footer footer = {0};

    int rc;
retry:
    rc = file_description_block(desc, unblock_request, 0);
    if (IS_ERR(rc))
        return rc;

    mutex_lock(&node->lock);
    struct virtq_desc_chain chain;
    if (!virtq_desc_chain_init(&chain, virtq, 3)) {
        mutex_unlock(&node->lock);
        goto retry;
    }
    virtq_desc_chain_push_buf(&chain, &header, sizeof(header), false);
    virtq_desc_chain_push_buf(&chain, buffer, count, device_writable);
    virtq_desc_chain_push_buf(&chain, &footer, sizeof(footer), true);
    rc = virtq_desc_chain_submit(&chain);
    mutex_unlock(&node->lock);
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

static ssize_t virtio_blk_do_io(file_description* desc, void* buffer,
                                size_t count, uint32_t type,
                                bool device_writable) {
    if (count % SECTOR_SIZE != 0)
        return -EINVAL;

    mutex_lock(&desc->offset_lock);

    if (desc->offset % SECTOR_SIZE != 0) {
        mutex_unlock(&desc->offset_lock);
        return -EINVAL;
    }
    uint64_t sector = desc->offset / SECTOR_SIZE;

    virtio_blk_device* node = (virtio_blk_device*)desc->inode;
    if (sector >= node->capacity) {
        mutex_unlock(&desc->offset_lock);
        return 0;
    }
    count = MIN(count, (node->capacity - sector) * SECTOR_SIZE);

    int rc = submit_request(desc, buffer, count, sector, type, device_writable);
    if (IS_ERR(rc)) {
        mutex_unlock(&desc->offset_lock);
        return rc;
    }

    desc->offset += count;
    mutex_unlock(&desc->offset_lock);

    return count;
}

static ssize_t virtio_blk_read(file_description* desc, void* buffer,
                               size_t count) {
    return virtio_blk_do_io(desc, buffer, count, VIRTIO_BLK_T_IN, true);
}

static ssize_t virtio_blk_write(file_description* desc, const void* buffer,
                                size_t count) {
    return virtio_blk_do_io(desc, (void*)buffer, count, VIRTIO_BLK_T_OUT,
                            false);
}

static int device_major;

static void virtio_blk_device_init(const struct pci_addr* addr) {
    struct virtio_pci_cap device_cfg_cap;
    if (!virtio_find_pci_cap(addr, VIRTIO_PCI_CAP_DEVICE_CFG,
                             &device_cfg_cap)) {
        kprint("virtio_blk: device is missing VIRTIO_PCI_CAP_DEVICE_CFG\n");
        return;
    }

    static size_t next_id = 0;
    if (next_id >= 26 * 26) {
        kprint("virtio_blk: too many devices\n");
        return;
    }

    struct virtio_device* virtio = virtio_device_create(addr, 1);
    if (IS_ERR(virtio)) {
        kprint("virtio_blk: failed to initialize a virtio device\n");
        return;
    }

    unsigned char* device_cfg_space = pci_map_bar(addr, device_cfg_cap.bar);
    if (IS_ERR(device_cfg_space))
        goto fail;
    volatile struct virtio_blk_config* blk_config =
        (volatile struct virtio_blk_config*)(device_cfg_space +
                                             device_cfg_cap.offset);
    uint64_t capacity = blk_config->capacity;
    kfree(device_cfg_space);

    size_t id = next_id++;
    dev_t rdev = makedev(device_major, id);
    char name[8] = "vd";
    if (id < 26) {
        name[2] = 'a' + id;
    } else {
        name[2] = 'a' + id / 26 - 1;
        name[3] = 'a' + id % 26;
    }

    struct virtio_blk_device* device =
        kmalloc(sizeof(struct virtio_blk_device));
    if (!device)
        goto fail;
    *device = (struct virtio_blk_device){0};

    device->virtio = virtio;
    device->capacity = capacity;

    struct inode* inode = &device->inode;
    static file_ops fops = {
        .destroy_inode = virtio_blk_destroy_inode,
        .read = virtio_blk_read,
        .write = virtio_blk_write,
    };
    inode->fops = &fops;
    inode->mode = S_IFBLK;
    inode->rdev = rdev;
    inode->ref_count = 1;

    ASSERT_OK(vfs_register_device(name, inode));
    return;

fail:
    virtio_device_destroy(virtio);
}

static void pci_device_callback(const struct pci_addr* addr, uint16_t vendor_id,
                                uint16_t device_id, void* ctx) {
    (void)ctx;
    if (vendor_id == 0x1af4 && device_id == 0x1001)
        virtio_blk_device_init(addr);
}

void virtio_blk_init(void) {
    device_major = vfs_generate_major_device_number();
    pci_enumerate_devices(pci_device_callback, NULL);
}
