#include "graphics.h"
#include "kernel/mem.h"
#include <common/errno.h>
#include <common/extra.h>
#include <common/string.h>
#include <kernel/asm_wrapper.h>
#include <kernel/fs/fs.h>
#include <kernel/kmalloc.h>
#include <kernel/pci.h>
#include <kernel/system.h>

#define VBE_DISPI_MAX_XRES 1024
#define VBE_DISPI_MAX_YRES 768

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

static uintptr_t framebuffer_addr;
static size_t framebuffer_width;
static size_t framebuffer_height;
static size_t framebuffer_pitch;

static void pci_enumeration_callback(uint8_t bus, uint8_t slot,
                                     uint8_t function, uint16_t vendor_id,
                                     uint16_t device_id) {
    if ((vendor_id == 0x1234 && device_id == 0x1111) |
        (vendor_id == 0x80ee && device_id == 0xbeef))
        framebuffer_addr = pci_get_bar0(bus, slot, function) & 0xfffffff0;
}

static void write_reg(uint16_t index, uint16_t data) {
    out16(VBE_DISPI_IOPORT_INDEX, index);
    out16(VBE_DISPI_IOPORT_DATA, data);
}

static void set_resolution(size_t width, size_t height) {
    framebuffer_width = MIN(width, VBE_DISPI_MAX_XRES);
    framebuffer_height = MIN(height, VBE_DISPI_MAX_YRES);
    framebuffer_pitch = framebuffer_width * 32;

    write_reg(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
    write_reg(VBE_DISPI_INDEX_XRES, framebuffer_width);
    write_reg(VBE_DISPI_INDEX_YRES, framebuffer_height);
    write_reg(VBE_DISPI_INDEX_VIRT_WIDTH, framebuffer_width);
    write_reg(VBE_DISPI_INDEX_VIRT_HEIGHT, framebuffer_height);
    write_reg(VBE_DISPI_INDEX_BPP, 32);
    write_reg(VBE_DISPI_INDEX_ENABLE,
              VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED);
}

void bochs_graphics_init(void) {
    pci_enumerate(pci_enumeration_callback);
    if (framebuffer_addr)
        set_resolution(640, 480);
}

static uintptr_t bochs_graphics_mmap(fs_node* node, uintptr_t vaddr,
                                     size_t length, int prot, off_t offset) {
    (void)node;
    (void)offset;
    mem_map_to_shared_physical_range(vaddr, framebuffer_addr, length,
                                     mem_prot_to_flags(prot));
    return vaddr;
}

static int bochs_graphics_ioctl(fs_node* node, int request, void* argp) {
    (void)node;

    switch (request) {
    case FBIOGET_RESOLUTION: {
        fb_resolution* r = (fb_resolution*)argp;
        r->width = framebuffer_width;
        r->height = framebuffer_height;
        r->pitch = framebuffer_pitch;
        return 0;
    }
    case FBIOSET_RESOLUTION: {
        fb_resolution* r = (fb_resolution*)argp;
        set_resolution(MIN(r->width, VBE_DISPI_MAX_XRES),
                       MIN(r->height, VBE_DISPI_MAX_YRES));
        r->width = framebuffer_width;
        r->height = framebuffer_height;
        r->pitch = framebuffer_pitch;
        return 0;
    }
    }

    return -EINVAL;
}

fs_node* bochs_graphics_device_create(void) {
    fs_node* node = kmalloc(sizeof(fs_node));
    if (!node)
        return NULL;

    memset(node, 0, sizeof(fs_node));

    node->name = kstrdup("bochs_graphics_device");
    if (!node->name)
        return NULL;

    node->flags = FS_BLOCK_DEVICE;
    node->mmap = bochs_graphics_mmap;
    node->ioctl = bochs_graphics_ioctl;
    return node;
}
