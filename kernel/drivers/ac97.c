#include "pci.h"
#include <kernel/api/err.h>
#include <kernel/api/sound.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/boot_defs.h>
#include <kernel/fs/fs.h>
#include <kernel/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/panic.h>
#include <kernel/safe_string.h>
#include <kernel/system.h>
#include <string.h>

#define PCI_CLASS_MULTIMEDIA 4
#define PCI_SUBCLASS_AUDIO_CONTROLLER 1
#define PCI_TYPE_MULTIMEDIA_AUDIO_CONTROLLER                                   \
    (PCI_CLASS_MULTIMEDIA << 8 | PCI_SUBCLASS_AUDIO_CONTROLLER)

#define BUS_PCM_OUT 0x10
#define BUS_GLOBAL_CONTROL 0x2c

#define MIXER_RESET_REGISTER 0x0
#define MIXER_MASTER_OUTPUT_VOLUME 0x2
#define MIXER_PCM_OUTPUT_VOLUME 0x18
#define MIXER_SAMPLE_RATE 0x2c

#define CHANNEL_BUFFER_DESCRIPTOR_LIST_PHYSICAL_ADDR 0x0
#define CHANNEL_CURRENT_INDEX 0x4
#define CHANNEL_LAST_VALID_INDEX 0x5
#define CHANNEL_STATUS 0x6
#define CHANNEL_TRANSFTER_CONTROL 0xb

#define GLOBAL_CONTROL_GLOBAL_INTERRUPT_ENABLE 0x1
#define GLOBAL_CONTROL_COLD_RESET 0x2

#define TRANSFER_STATUS_DMA_CONTROLLER 0x1
#define TRANSFER_STATUS_LAST_BUFFER_ENTRY_TRANSFERRED 0x4
#define TRANSFER_STATUS_IOC 0x8
#define TRANSFER_STATUS_FIFO_ERROR 0x10

#define TRANSFER_CONTROL_DMA_CONTROLLER 0x1
#define TRANSFER_CONTROL_RESET 0x2
#define TRANSFER_CONTROL_IOC_INTERRUPT_ENABLE 0x8
#define TRANSFER_CONTROL_FIFO_ERROR_INTERRUPT_ENABLE 0x10

#define BUFFER_DESCRIPTOR_LIST_INTERRUPT_ON_COMPLETION 0x8000

static struct pci_addr device_addr;
static uint16_t mixer_base;
static uint16_t bus_base;
static uint16_t pcm_out_channel;

static void pci_device_callback(const struct pci_addr* addr, uint16_t vendor_id,
                                uint16_t device_id, bool* detected) {
    (void)vendor_id;
    (void)device_id;
    if (pci_get_type(addr) == PCI_TYPE_MULTIMEDIA_AUDIO_CONTROLLER) {
        *detected = true;
        device_addr = *addr;
        mixer_base = pci_get_bar(addr, 0) & ~PCI_BAR_SPACE;
        bus_base = pci_get_bar(addr, 1) & ~PCI_BAR_SPACE;
    }
}

static atomic_bool dma_is_running = false;
static atomic_bool buffer_descriptor_list_is_full = false;

static void irq_handler(struct registers* regs) {
    (void)regs;

    uint16_t status = in16(pcm_out_channel + CHANNEL_STATUS);
    if (!(status & TRANSFER_STATUS_IOC))
        return;
    status = TRANSFER_STATUS_LAST_BUFFER_ENTRY_TRANSFERRED;
    status |= TRANSFER_STATUS_IOC;
    status |= TRANSFER_STATUS_FIFO_ERROR;
    out16(pcm_out_channel + CHANNEL_STATUS, status);

    if (status & TRANSFER_STATUS_DMA_CONTROLLER)
        dma_is_running = false;

    buffer_descriptor_list_is_full = false;
}

#define OUTPUT_BUF_NUM_PAGES 4

alignas(PAGE_SIZE) static unsigned char output_buf[OUTPUT_BUF_NUM_PAGES *
                                                   PAGE_SIZE];
static uint8_t output_buf_page_idx = 0;

#define BUFFER_DESCRIPTOR_LIST_MAX_NUM_ENTRIES 32

struct buffer_descriptor_list_entry {
    uint32_t phys_addr;
    uint16_t num_samples;
    uint16_t control;
} __attribute__((packed));

static struct buffer_descriptor_list_entry
    buffer_descriptor_list[BUFFER_DESCRIPTOR_LIST_MAX_NUM_ENTRIES];
static uint8_t buffer_descriptor_list_idx = 0;

static bool can_write(void) { return !buffer_descriptor_list_is_full; }

static bool unblock_write(struct file* file) {
    (void)file;
    return can_write();
}

static void start_dma(void) {
    uint8_t control = in8(pcm_out_channel + CHANNEL_TRANSFTER_CONTROL);
    control |= TRANSFER_CONTROL_DMA_CONTROLLER;
    control |= TRANSFER_CONTROL_FIFO_ERROR_INTERRUPT_ENABLE;
    control |= TRANSFER_CONTROL_IOC_INTERRUPT_ENABLE;
    out8(pcm_out_channel + CHANNEL_TRANSFTER_CONTROL, control);
    dma_is_running = true;
}

static int write_single_buffer(struct file* file, const void* buffer,
                               size_t count) {
    bool int_flag = push_cli();
    do {
        uint8_t current_idx = in8(pcm_out_channel + CHANNEL_CURRENT_INDEX);
        uint8_t last_valid_idx =
            in8(pcm_out_channel + CHANNEL_LAST_VALID_INDEX);
        int head_distance = (int)last_valid_idx - (int)current_idx;
        if (head_distance < 0)
            head_distance += BUFFER_DESCRIPTOR_LIST_MAX_NUM_ENTRIES;
        if (dma_is_running)
            ++head_distance;

        if (head_distance > OUTPUT_BUF_NUM_PAGES) {
            buffer_descriptor_list_idx = current_idx + 1;
            break;
        }

        if (head_distance < OUTPUT_BUF_NUM_PAGES)
            break;

        buffer_descriptor_list_is_full = true;
        int rc = file_block(file, unblock_write, 0);
        if (IS_ERR(rc)) {
            pop_cli(int_flag);
            return rc;
        }
    } while (dma_is_running);
    pop_cli(int_flag);

    unsigned char* dest = output_buf + PAGE_SIZE * output_buf_page_idx;
    memcpy(dest, buffer, count);

    struct buffer_descriptor_list_entry* entry =
        buffer_descriptor_list + buffer_descriptor_list_idx;
    entry->phys_addr = virt_to_phys(dest);
    entry->num_samples = count / sizeof(uint16_t);
    entry->control = BUFFER_DESCRIPTOR_LIST_INTERRUPT_ON_COMPLETION;

    out32(pcm_out_channel + CHANNEL_BUFFER_DESCRIPTOR_LIST_PHYSICAL_ADDR,
          virt_to_phys(buffer_descriptor_list));
    out8(pcm_out_channel + CHANNEL_LAST_VALID_INDEX,
         buffer_descriptor_list_idx);

    if (!dma_is_running)
        start_dma();

    output_buf_page_idx = (output_buf_page_idx + 1) % OUTPUT_BUF_NUM_PAGES;
    buffer_descriptor_list_idx = (buffer_descriptor_list_idx + 1) %
                                 BUFFER_DESCRIPTOR_LIST_MAX_NUM_ENTRIES;

    return 0;
}

static ssize_t ac97_device_write(struct file* file, const void* buffer,
                                 size_t count) {
    unsigned char* src = (unsigned char*)buffer;
    size_t nwritten = 0;
    while (count > 0) {
        size_t size = MIN(PAGE_SIZE, count);
        int rc = write_single_buffer(file, src, size);
        if (IS_ERR(rc))
            return rc;
        src += size;
        count -= size;
        nwritten += size;
    }
    return nwritten;
}

static int ac97_device_ioctl(struct file* file, int request, void* user_argp) {
    (void)file;

    switch (request) {
    case SOUND_GET_SAMPLE_RATE: {
        uint16_t value = in16(mixer_base + MIXER_SAMPLE_RATE);
        if (!copy_to_user(user_argp, &value, sizeof(uint16_t)))
            return -EFAULT;
        return 0;
    }
    case SOUND_SET_SAMPLE_RATE: {
        uint16_t value;
        if (!copy_from_user(&value, user_argp, sizeof(uint16_t)))
            return -EFAULT;
        out16(mixer_base + MIXER_SAMPLE_RATE, value);
        value = in16(mixer_base + MIXER_SAMPLE_RATE);
        if (dma_is_running)
            start_dma();
        if (!copy_to_user(user_argp, &value, sizeof(uint16_t)))
            return -EFAULT;
        return 0;
    }
    case SOUND_GET_ATTENUATION: {
        uint16_t value = in16(mixer_base + MIXER_MASTER_OUTPUT_VOLUME);
        if (!copy_to_user(user_argp, &value, sizeof(uint16_t)))
            return -EFAULT;
        return 0;
    }
    case SOUND_SET_ATTENUATION: {
        uint16_t value;
        if (!copy_from_user(&value, user_argp, sizeof(uint16_t)))
            return -EFAULT;
        out16(mixer_base + MIXER_MASTER_OUTPUT_VOLUME, value);
        value = in16(mixer_base + MIXER_MASTER_OUTPUT_VOLUME);
        if (!copy_to_user(user_argp, &value, sizeof(uint16_t)))
            return -EFAULT;
        return 0;
    }
    }
    return -EINVAL;
}

static short ac97_device_poll(struct file* file, short events) {
    (void)file;
    short revents = 0;
    if (events & POLLIN)
        revents |= POLLIN;
    if ((events & POLLOUT) && can_write())
        revents |= POLLOUT;
    return revents;
}

static struct inode* ac97_device_get(void) {
    static struct file_ops fops = {
        .write = ac97_device_write,
        .ioctl = ac97_device_ioctl,
        .poll = ac97_device_poll,
    };
    static struct inode inode = {
        .fops = &fops,
        .mode = S_IFCHR,
        .rdev = makedev(14, 3),
        .ref_count = 1,
    };
    return &inode;
}

void ac97_init(void) {
    bool detected = false;
    pci_enumerate_devices((pci_device_callback_fn)pci_device_callback,
                          &detected);
    if (!detected)
        return;
    kprintf("ac97: detected device %x:%x:%x\n", device_addr.bus,
            device_addr.slot, device_addr.function);

    pci_set_interrupt_line_enabled(&device_addr, true);
    pci_set_bus_mastering_enabled(&device_addr, true);

    uint32_t control = in32(bus_base + BUS_GLOBAL_CONTROL);
    control |= GLOBAL_CONTROL_GLOBAL_INTERRUPT_ENABLE;
    control |= GLOBAL_CONTROL_COLD_RESET;
    out32(bus_base + BUS_GLOBAL_CONTROL, control);

    out16(mixer_base + MIXER_RESET_REGISTER, 1);

    out16(mixer_base + MIXER_SAMPLE_RATE, 48000);

    // zero attenuation i.e. full volume
    out16(mixer_base + MIXER_MASTER_OUTPUT_VOLUME, 0);
    out16(mixer_base + MIXER_PCM_OUTPUT_VOLUME, 0);

    pcm_out_channel = bus_base + BUS_PCM_OUT;
    out8(pcm_out_channel + CHANNEL_TRANSFTER_CONTROL, TRANSFER_CONTROL_RESET);
    while (in8(pcm_out_channel + CHANNEL_TRANSFTER_CONTROL) &
           TRANSFER_CONTROL_RESET)
        delay(50);

    uint8_t irq_num = pci_get_interrupt_line(&device_addr);
    idt_set_interrupt_handler(IRQ(irq_num), irq_handler);

    ASSERT_OK(vfs_register_device("dsp", ac97_device_get()));
}
