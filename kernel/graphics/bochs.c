#include <kernel/api/err.h>
#include <kernel/api/fb.h>
#include <kernel/api/stat.h>
#include <kernel/api/sysmacros.h>
#include <kernel/asm_wrapper.h>
#include <kernel/fs/fs.h>
#include <kernel/kmalloc.h>
#include <kernel/kprintf.h>
#include <kernel/lock.h>
#include <kernel/mem.h>
#include <kernel/panic.h>
#include <kernel/pci.h>
#include <kernel/system.h>
#include <string.h>

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

static uintptr_t fb_paddr;
static struct fb_info fb_info;
static mutex lock;

static void pci_enumeration_callback(uint8_t bus, uint8_t slot,
                                     uint8_t function, uint16_t vendor_id,
                                     uint16_t device_id) {
    if ((vendor_id == 0x1234 && device_id == 0x1111) |
        (vendor_id == 0x80ee && device_id == 0xbeef))
        fb_paddr = pci_get_bar0(bus, slot, function) & 0xfffffff0;
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

    fb_info.width = read_reg(VBE_DISPI_INDEX_XRES);
    fb_info.height = read_reg(VBE_DISPI_INDEX_YRES);
    fb_info.bpp = read_reg(VBE_DISPI_INDEX_BPP);
    fb_info.pitch = fb_info.width * (fb_info.bpp / 8);
}

bool bochs_fb_init(void) {
    pci_enumerate(pci_enumeration_callback);
    if (!fb_paddr)
        return false;

    kprintf("Found framebuffer at P0x%x\n", fb_paddr);
    configure(640, 480, 32);
    mutex_init(&lock);
    return true;
}

static uintptr_t bochs_fb_device_mmap(file_description* desc, uintptr_t addr,
                                      size_t length, int prot, off_t offset,
                                      bool shared) {
    (void)desc;
    if (offset != 0)
        return -ENXIO;
    if (!shared)
        return -ENODEV;

    int rc = mem_map_to_physical_range(
        addr, fb_paddr, length, mem_prot_to_map_flags(prot) | MEM_SHARED);
    if (IS_ERR(rc))
        return rc;
    return addr;
}

static int bochs_fb_device_ioctl(file_description* desc, int request,
                                 void* argp) {
    (void)desc;
    switch (request) {
    case FBIOGET_INFO: {
        mutex_lock(&lock);
        *(struct fb_info*)argp = fb_info;
        mutex_unlock(&lock);
        return 0;
    }
    case FBIOSET_INFO: {
        struct fb_info* request = (struct fb_info*)argp;
        mutex_lock(&lock);
        configure(request->width, request->height, request->bpp);
        *(struct fb_info*)argp = fb_info;
        mutex_unlock(&lock);
        return 0;
    }
    }
    return -EINVAL;
}

struct file* bochs_fb_device_create(void) {
    struct file* file = kmalloc(sizeof(struct file));
    if (!file)
        return ERR_PTR(-ENOMEM);
    *file = (struct file){0};

    file->name = kstrdup("bochs_fb_device");
    if (!file->name)
        return ERR_PTR(-ENOMEM);

    file->mode = S_IFBLK;
    file->mmap = bochs_fb_device_mmap;
    file->ioctl = bochs_fb_device_ioctl;
    file->device_id = makedev(29, 0);
    return file;
}
