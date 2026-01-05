#include <kernel/api/err.h>
#include <kernel/asm_wrapper.h>
#include <kernel/drivers/graphics/graphics.h>
#include <kernel/drivers/pci.h>
#include <kernel/kmsg.h>
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

static struct fb_info info = {
    .id = "bochs",
};
static struct mutex lock;

static void pci_device_callback(const struct pci_addr* addr, uint16_t vendor_id,
                                uint16_t device_id, void* ctx) {
    (void)ctx;
    if ((vendor_id == 0x1234 && device_id == 0x1111) ||
        (vendor_id == 0x80ee && device_id == 0xbeef))
        info.phys_addr = pci_get_bar(addr, 0) & 0xfffffff0;
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
    SCOPED_LOCK(mutex, &lock);
    *out_info = info;
    return 0;
}

static int bochs_fb_set_info(struct fb_info* inout_info) {
    SCOPED_LOCK(mutex, &lock);
    configure(inout_info->width, inout_info->height, inout_info->bpp);
    *inout_info = info;
    return 0;
}

struct fb* bochs_fb_init(void) {
    pci_enumerate_devices(pci_device_callback, NULL);
    if (!info.phys_addr)
        return NULL;

    kprintf("bochs_fb: found framebuffer at P%#zx\n", info.phys_addr);
    configure(640, 480, 32);

    static struct fb fb = {
        .get_info = bochs_fb_get_info,
        .set_info = bochs_fb_set_info,
    };
    return &fb;
}
