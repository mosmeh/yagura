#include "graphics.h"
#include <kernel/api/err.h>
#include <kernel/asm_wrapper.h>
#include <kernel/drivers/pci.h>
#include <kernel/kprintf.h>
#include <kernel/lock.h>
#include <kernel/memory/memory.h>

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

static uintptr_t paddr;
static struct fb_info info;
static mutex lock;

static void pci_enumeration_callback(const struct pci_addr* addr,
                                     uint16_t vendor_id, uint16_t device_id) {
    if ((vendor_id == 0x1234 && device_id == 0x1111) ||
        (vendor_id == 0x80ee && device_id == 0xbeef))
        paddr = pci_get_bar0(addr) & 0xfffffff0;
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

static int bochs_fb_get_info(struct fb_info* out_info) {
    mutex_lock(&lock);
    *out_info = info;
    mutex_unlock(&lock);
    return 0;
}

static int bochs_fb_set_info(struct fb_info* inout_info) {
    mutex_lock(&lock);
    configure(inout_info->width, inout_info->height, inout_info->bpp);
    *inout_info = info;
    mutex_unlock(&lock);
    return 0;
}

static int bochs_fb_mmap(uintptr_t addr, size_t length, off_t offset,
                         uint16_t page_flags) {
    if (offset != 0)
        return -ENXIO;
    if (!(page_flags & PAGE_SHARED))
        return -ENODEV;

    return paging_map_to_physical_range(addr, paddr, length, page_flags);
}

struct fb* bochs_fb_init(void) {
    pci_enumerate(pci_enumeration_callback);
    if (!paddr)
        return NULL;

    kprintf("Found framebuffer at P0x%x\n", paddr);
    configure(640, 480, 32);

    static struct fb fb = {.get_info = bochs_fb_get_info,
                           .set_info = bochs_fb_set_info,
                           .mmap = bochs_fb_mmap};
    return &fb;
}
