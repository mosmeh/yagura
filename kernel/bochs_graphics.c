#include "api/err.h"
#include "api/fb.h"
#include "api/stat.h"
#include "asm_wrapper.h"
#include "fs/fs.h"
#include "kernel/mem.h"
#include "kmalloc.h"
#include "kprintf.h"
#include "lock.h"
#include "panic.h"
#include "pci.h"
#include "system.h"
#include <common/string.h>

#define VBE_DISPI_IOPORT_INDEX 0x01ce
#define VBE_DISPI_IOPORT_DATA 0x01cf

#define VBE_DISPI_INDEX_ID 0x0
#define VBE_DISPI_INDEX_XRES 0x1
#define VBE_DISPI_INDEX_YRES 0x2
#define VBE_DISPI_INDEX_BPP 0x3
#define VBE_DISPI_INDEX_ENABLE 0x4
#define VBE_DISPI_INDEX_BANK 0x5
#define VBE_DISPI_INDEX_VIRT_WIDTH 0x6
#define VBE_DISPI_INDEX_VIRT_HEIGHT 0x7
#define VBE_DISPI_INDEX_X_OFFSET 0x8
#define VBE_DISPI_INDEX_Y_OFFSET 0x9

#define VBE_DISPI_DISABLED 0x00
#define VBE_DISPI_ENABLED 0x01
#define VBE_DISPI_LFB_ENABLED 0x40

static uintptr_t fb_addr;
static fb_info info;
static mutex lock;

static void pci_enumeration_callback(uint8_t bus, uint8_t slot,
                                     uint8_t function, uint16_t vendor_id,
                                     uint16_t device_id) {
    if ((vendor_id == 0x1234 && device_id == 0x1111) |
        (vendor_id == 0x80ee && device_id == 0xbeef))
        fb_addr = pci_get_bar0(bus, slot, function) & 0xfffffff0;
}

static uint16_t read_reg(uint16_t index) {
    out16(VBE_DISPI_IOPORT_INDEX, index);
    return in16(VBE_DISPI_IOPORT_DATA);
}

static void write_reg(uint16_t index, uint16_t data) {
    out16(VBE_DISPI_IOPORT_INDEX, index);
    out16(VBE_DISPI_IOPORT_DATA, data);
}

static void configure(size_t width, size_t height, size_t bpp) {
    write_reg(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
    write_reg(VBE_DISPI_INDEX_XRES, width);
    write_reg(VBE_DISPI_INDEX_YRES, height);
    write_reg(VBE_DISPI_INDEX_VIRT_WIDTH, width);
    write_reg(VBE_DISPI_INDEX_VIRT_HEIGHT, height);
    write_reg(VBE_DISPI_INDEX_BPP, bpp);
    write_reg(VBE_DISPI_INDEX_ENABLE,
              VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED);

    info.width = read_reg(VBE_DISPI_INDEX_XRES);
    info.height = read_reg(VBE_DISPI_INDEX_YRES);
    info.bpp = read_reg(VBE_DISPI_INDEX_BPP);
    info.pitch = info.width * (info.bpp / 8);
}

void bochs_graphics_init(void) {
    pci_enumerate(pci_enumeration_callback);
    KASSERT(fb_addr);
    kprintf("Found framebuffer at 0x%x\n", fb_addr);
    configure(640, 480, 32);
    mutex_init(&lock);
}

static uintptr_t bochs_graphics_mmap(file_description* desc, uintptr_t vaddr,
                                     size_t length, int prot, off_t offset) {
    (void)desc;
    (void)offset;
    int rc = mem_map_to_shared_physical_range(vaddr, fb_addr, length,
                                              mem_prot_to_flags(prot));
    if (IS_ERR(rc))
        return rc;
    return vaddr;
}

static int bochs_graphics_ioctl(file_description* desc, int request,
                                void* argp) {
    (void)desc;

    switch (request) {
    case FBIOGET_INFO: {
        mutex_lock(&lock);
        *(fb_info*)argp = info;
        mutex_unlock(&lock);
        return 0;
    }
    case FBIOSET_INFO: {
        fb_info* request = (fb_info*)argp;
        mutex_lock(&lock);
        configure(request->width, request->height, request->bpp);
        *(fb_info*)argp = info;
        mutex_unlock(&lock);
        return 0;
    }
    }

    return -EINVAL;
}

fs_node* bochs_graphics_device_create(void) {
    fs_node* node = kmalloc(sizeof(fs_node));
    if (!node)
        return ERR_PTR(-ENOMEM);

    memset(node, 0, sizeof(fs_node));

    node->name = kstrdup("bochs_graphics_device");
    if (!node->name)
        return ERR_PTR(-ENOMEM);

    node->mode = S_IFBLK;
    node->mmap = bochs_graphics_mmap;
    node->ioctl = bochs_graphics_ioctl;
    return node;
}
