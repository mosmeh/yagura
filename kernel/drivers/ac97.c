#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/linux/major.h>
#include <kernel/api/linux/sound.h>
#include <kernel/api/linux/soundcard.h>
#include <kernel/api/sys/poll.h>
#include <kernel/api/sys/sysmacros.h>
#include <kernel/arch/io.h>
#include <kernel/device/device.h>
#include <kernel/drivers/pci.h>
#include <kernel/fs/file.h>
#include <kernel/interrupts.h>
#include <kernel/kmsg.h>
#include <kernel/memory/memory.h>
#include <kernel/memory/safe_string.h>
#include <kernel/panic.h>
#include <kernel/sched.h>
#include <kernel/system.h>

#define PCI_CLASS_MULTIMEDIA 4
#define PCI_SUBCLASS_AUDIO_CONTROLLER 1
#define PCI_TYPE_MULTIMEDIA_AUDIO_CONTROLLER                                   \
    (PCI_CLASS_MULTIMEDIA << 8 | PCI_SUBCLASS_AUDIO_CONTROLLER)

#define BUS_PCM_OUT 0x10
#define BUS_GLOBAL_CONTROL 0x2c

#define MIXER_RESET 0x0
#define MIXER_MASTER_VOLUME 0x2
#define MIXER_PCM_OUT_VOLUME 0x18
#define MIXER_EXTENDED_AUDIO_ID 0x28
#define MIXER_EXTENDED_AUDIO_STAT_CTRL 0x2a
#define MIXER_PCM_FRONT_DAC_RATE 0x2c

#define VOLUME_MUTE 0x8000

#define EXTENDED_AUDIO_ID_VARIABLE_RATE_AUDIO 0x1
#define EXTENDED_AUDIO_STAT_CTRL_VARIABLE_RATE_AUDIO 0x1

#define PCM_OUT_BUFFER_DESCRIPTOR_LIST_BASE_ADDR (BUS_PCM_OUT + 0x0)
#define PCM_OUT_CURRENT_INDEX_VALUE (BUS_PCM_OUT + 0x4)
#define PCM_OUT_LAST_VALID_INDEX (BUS_PCM_OUT + 0x5)
#define PCM_OUT_STATUS (BUS_PCM_OUT + 0x6)
#define PCM_OUT_CONTROL (BUS_PCM_OUT + 0xb)

#define GLOBAL_CONTROL_GPI_INTERRUPT_ENABLE 0x1
#define GLOBAL_CONTROL_AC97_COLD_RESET 0x2

#define STATUS_DMA_CONTROLLER_HALTED 0x1
#define STATUS_LAST_VALID_BUFFER_COMPLETION_INTERRUPT 0x4
#define STATUS_BUFFER_COMPLETION_INTERRUPT_STATUS 0x8
#define STATUS_FIFO_ERROR 0x10

#define CONTROL_RUN_PAUSE_BUS_MASTER 0x1
#define CONTROL_RESET_REGISTERS 0x2
#define CONTROL_INTERRUPT_ON_COMPLETION_ENABLE 0x10

#define BUFFER_DESCRIPTOR_INTERRUPT_ON_COMPLETION 0x8000

static struct pci_addr device_addr;
static uint16_t mixer_base;
static uint16_t bus_base;

static void pci_device_callback(const struct pci_addr* addr, uint16_t vendor_id,
                                uint16_t device_id, void* ctx) {
    (void)vendor_id;
    (void)device_id;
    bool* detected = ctx;
    if (pci_get_type(addr) == PCI_TYPE_MULTIMEDIA_AUDIO_CONTROLLER) {
        *detected = true;
        device_addr = *addr;
        mixer_base = pci_get_bar(addr, 0) & ~PCI_BAR_SPACE;
        bus_base = pci_get_bar(addr, 1) & ~PCI_BAR_SPACE;
    }
}

static _Atomic(bool) dma_is_running;
static _Atomic(bool) buffer_descriptor_list_is_full;

static void irq_handler(struct registers* regs) {
    (void)regs;

    uint16_t status = in16(bus_base + PCM_OUT_STATUS);
    if (!(status & STATUS_BUFFER_COMPLETION_INTERRUPT_STATUS))
        return;

    out16(bus_base + PCM_OUT_STATUS,
          STATUS_LAST_VALID_BUFFER_COMPLETION_INTERRUPT |
              STATUS_BUFFER_COMPLETION_INTERRUPT_STATUS | STATUS_FIFO_ERROR);

    if (status & STATUS_DMA_CONTROLLER_HALTED)
        dma_is_running = false;

    buffer_descriptor_list_is_full = false;
}

#define OUTPUT_BUF_NUM_PAGES 4

_Alignas(PAGE_SIZE) static unsigned char output_buf[OUTPUT_BUF_NUM_PAGES
                                                    << PAGE_SHIFT];
static uint8_t output_buf_page_idx;

#define MAX_NUM_BUFFER_DESCRIPTORS 32

struct buffer_descriptor {
    uint32_t phys_addr;
    uint16_t num_samples;
    uint16_t control;
} __attribute__((packed));

static struct buffer_descriptor
    buffer_descriptor_list[MAX_NUM_BUFFER_DESCRIPTORS];
static uint8_t buffer_descriptor_idx;

static bool can_write(void) { return !buffer_descriptor_list_is_full; }

static bool unblock_write(struct file* file) {
    (void)file;
    return can_write();
}

static void start_dma(void) {
    uint8_t control = in8(bus_base + PCM_OUT_CONTROL);
    control |= CONTROL_RUN_PAUSE_BUS_MASTER;
    control |= CONTROL_INTERRUPT_ON_COMPLETION_ENABLE;
    out8(bus_base + PCM_OUT_CONTROL, control);
    dma_is_running = true;
}

static struct mutex lock;

NODISCARD static int
write_single_buffer(struct file* file, const void* user_buffer, size_t count) {
    mutex_lock(&lock);

    for (;;) {
        uint8_t current_idx = in8(bus_base + PCM_OUT_CURRENT_INDEX_VALUE);
        uint8_t last_valid_idx = in8(bus_base + PCM_OUT_LAST_VALID_INDEX);
        int head_distance = (int)last_valid_idx - (int)current_idx;
        if (head_distance < 0)
            head_distance += MAX_NUM_BUFFER_DESCRIPTORS;
        if (dma_is_running)
            ++head_distance;

        if (head_distance > OUTPUT_BUF_NUM_PAGES) {
            buffer_descriptor_idx = current_idx + 1;
            break;
        }

        if (head_distance < OUTPUT_BUF_NUM_PAGES)
            break;

        buffer_descriptor_list_is_full = true;

        mutex_unlock(&lock);

        int rc = file_block(file, unblock_write, 0);
        if (IS_ERR(rc))
            return rc;

        mutex_lock(&lock);

        if (!dma_is_running)
            break;
    }

    ASSERT(mutex_is_locked_by_current(&lock));

    unsigned char* dest = output_buf + PAGE_SIZE * output_buf_page_idx;
    if (copy_from_user(dest, user_buffer, count)) {
        mutex_unlock(&lock);
        return -EFAULT;
    }

    struct buffer_descriptor* entry =
        buffer_descriptor_list + buffer_descriptor_idx;
    entry->phys_addr = virt_to_phys(dest);
    entry->num_samples = count / sizeof(uint16_t);
    entry->control = BUFFER_DESCRIPTOR_INTERRUPT_ON_COMPLETION;

    out32(bus_base + PCM_OUT_BUFFER_DESCRIPTOR_LIST_BASE_ADDR,
          virt_to_phys(buffer_descriptor_list));
    out8(bus_base + PCM_OUT_LAST_VALID_INDEX, buffer_descriptor_idx);

    if (!dma_is_running)
        start_dma();

    output_buf_page_idx = (output_buf_page_idx + 1) % OUTPUT_BUF_NUM_PAGES;
    buffer_descriptor_idx =
        (buffer_descriptor_idx + 1) % MAX_NUM_BUFFER_DESCRIPTORS;

    mutex_unlock(&lock);
    return 0;
}

static ssize_t ac97_dsp_pwrite(struct file* file, const void* user_buffer,
                               size_t count, uint64_t offset) {
    (void)offset;
    const unsigned char* user_src = user_buffer;
    size_t nwritten = 0;
    while (count > 0) {
        size_t size = MIN(PAGE_SIZE, count);
        int rc = write_single_buffer(file, user_src, size);
        if (rc == -EINTR && nwritten > 0)
            return nwritten;
        if (IS_ERR(rc))
            return rc;
        user_src += size;
        count -= size;
        nwritten += size;
    }
    return nwritten;
}

static unsigned get_sample_rate(void) {
    ASSERT(mutex_is_locked_by_current(&lock));
    return in16(mixer_base + MIXER_PCM_FRONT_DAC_RATE);
}

static bool variable_rate_audio_supported;

static void set_sample_rate(int sample_rate) {
    ASSERT(mutex_is_locked_by_current(&lock));

    if (!variable_rate_audio_supported)
        sample_rate = 48000;

    if (sample_rate < 1000)
        sample_rate = 1000;
    else if (sample_rate > UINT16_MAX)
        sample_rate = UINT16_MAX;

    out16(mixer_base + MIXER_PCM_FRONT_DAC_RATE, sample_rate);
    if (dma_is_running)
        start_dma();
}

static unsigned map_inverted(unsigned value, unsigned from_max,
                             unsigned to_max) {
    if (value >= from_max)
        return 0;
    return to_max - value * to_max / from_max;
}

struct channel {
    uint16_t reg;
    unsigned volume_mask;
};

static struct channel channels[] = {
    [SOUND_MIXER_VOLUME] = {MIXER_MASTER_VOLUME, 0},
    [SOUND_MIXER_PCM] = {MIXER_PCM_OUT_VOLUME, 0},
};

static struct channel* channel_get(size_t index) {
    if (index >= ARRAY_SIZE(channels))
        return NULL;
    struct channel* channel = &channels[index];
    if (!channel->reg)
        return NULL;
    return channel;
}

static void channel_init(struct channel* channel) {
    ASSERT(mutex_is_locked_by_current(&lock));

    // Measure the precision of the volume control
    for (size_t i = 0; i < 6; ++i) {
        uint16_t volume = 1 << i;
        uint16_t value = volume | (volume << 8) | VOLUME_MUTE;
        out16(mixer_base + channel->reg, value);
        if (in16(mixer_base + channel->reg) != value)
            break;
        channel->volume_mask = (1 << (i + 1)) - 1;
    }
}

// AC'97 and OSS use different volume formats:
// - AC'97:
//   - left in high byte, right in low byte
//   - 0 -> max volume, full bits set -> quietest, VOLUME_MUTE bit -> mute
// - OSS:
//   - left in low byte, right in high byte
//   - 0 -> mute, 100 -> max volume

static unsigned channel_get_volume(const struct channel* channel) {
    ASSERT(mutex_is_locked_by_current(&lock));

    uint16_t native_value = in16(mixer_base + channel->reg);

    unsigned left = MIN((native_value >> 8) & 0x3f, channel->volume_mask);
    unsigned right = MIN(native_value & 0x3f, channel->volume_mask);
    left = map_inverted(left, channel->volume_mask, 100);
    right = map_inverted(right, channel->volume_mask, 100);

    return left | (right << 8);
}

static void channel_set_volume(const struct channel* channel, unsigned value) {
    ASSERT(mutex_is_locked_by_current(&lock));

    unsigned left = value & 0xff;
    unsigned right = (value >> 8) & 0xff;
    left = map_inverted(left, 100, channel->volume_mask);
    right = map_inverted(right, 100, channel->volume_mask);

    uint16_t native_value = ((left & 0x3f) << 8) | (right & 0x3f);
    if (value == 0)
        native_value |= VOLUME_MUTE;

    out16(mixer_base + channel->reg, native_value);
}

static void mixer_reset(void) {
    SCOPED_LOCK(mutex, &lock);

    out16(mixer_base + MIXER_RESET, 1);

    uint16_t extended_audio_id = in16(mixer_base + MIXER_EXTENDED_AUDIO_ID);
    uint16_t extended_audio_stat_ctrl =
        in16(mixer_base + MIXER_EXTENDED_AUDIO_STAT_CTRL);
    if (extended_audio_id & EXTENDED_AUDIO_ID_VARIABLE_RATE_AUDIO) {
        extended_audio_stat_ctrl |=
            EXTENDED_AUDIO_STAT_CTRL_VARIABLE_RATE_AUDIO;
        variable_rate_audio_supported = true;
    }
    out16(mixer_base + MIXER_EXTENDED_AUDIO_STAT_CTRL,
          extended_audio_stat_ctrl);

    for (size_t i = 0; i < ARRAY_SIZE(channels); ++i) {
        struct channel* channel = channel_get(i);
        if (!channel)
            continue;
        channel_init(channel);
        channel_set_volume(channel, 100 | (100 << 8)); // Max volume
    }
}

static int ac97_mixer_ioctl(struct file* file, unsigned cmd,
                            unsigned long arg) {
    (void)file;
    switch (cmd) {
    case SOUND_MIXER_READ_VOLUME:
    case SOUND_MIXER_READ_PCM: {
        int value;
        {
            SCOPED_LOCK(mutex, &lock);
            const struct channel* channel = ASSERT(channel_get(_IOC_NR(cmd)));
            value = channel_get_volume(channel);
        }
        if (copy_to_user((void*)arg, &value, sizeof(int)))
            return -EFAULT;
        return 0;
    }
    case SOUND_MIXER_WRITE_VOLUME:
    case SOUND_MIXER_WRITE_PCM: {
        int value;
        if (copy_from_user(&value, (const void*)arg, sizeof(int)))
            return -EFAULT;
        {
            SCOPED_LOCK(mutex, &lock);
            const struct channel* channel = ASSERT(channel_get(_IOC_NR(cmd)));
            channel_set_volume(channel, value);
            value = channel_get_volume(channel);
        }
        if (copy_to_user((void*)arg, &value, sizeof(int)))
            return -EFAULT;
        return 0;
    }
    case SOUND_MIXER_READ_DEVMASK:
    case SOUND_MIXER_READ_STEREODEVS: {
        int value = SOUND_MASK_VOLUME | SOUND_MASK_PCM;
        if (copy_to_user((void*)arg, &value, sizeof(int)))
            return -EFAULT;
        return 0;
    }
    case SOUND_MIXER_READ_RECSRC:
    case SOUND_MIXER_READ_RECMASK:
    case SOUND_MIXER_READ_CAPS: {
        int value = 0;
        if (copy_to_user((void*)arg, &value, sizeof(int)))
            return -EFAULT;
        return 0;
    }
    }
    return -ENXIO;
}

static void dsp_reset(void) {
    SCOPED_LOCK(mutex, &lock);

    out8(bus_base + PCM_OUT_CONTROL, 0);
    out8(bus_base + PCM_OUT_CONTROL, CONTROL_RESET_REGISTERS);
    while (in8(bus_base + PCM_OUT_CONTROL) & CONTROL_RESET_REGISTERS)
        delay(50);

    out16(bus_base + PCM_OUT_STATUS,
          STATUS_LAST_VALID_BUFFER_COMPLETION_INTERRUPT |
              STATUS_BUFFER_COMPLETION_INTERRUPT_STATUS | STATUS_FIFO_ERROR);

    dma_is_running = buffer_descriptor_list_is_full = false;
    output_buf_page_idx = buffer_descriptor_idx = 0;
}

static bool unblock_sync(struct file* file) {
    (void)file;
    return !dma_is_running;
}

static int ac97_dsp_ioctl(struct file* file, unsigned cmd, unsigned long arg) {
    (void)file;

    if (_IOC_TYPE(cmd) == 'M')
        return ac97_mixer_ioctl(file, cmd, arg);

    switch (cmd) {
    case SNDCTL_DSP_RESET:
        dsp_reset();
        return 0;
    case SNDCTL_DSP_SYNC:
        return file_block(file, unblock_sync, 0);
    case SOUND_PCM_READ_RATE: {
        int value;
        {
            SCOPED_LOCK(mutex, &lock);
            value = get_sample_rate();
        }
        if (copy_to_user((void*)arg, &value, sizeof(int)))
            return -EFAULT;
        return 0;
    }
    case SNDCTL_DSP_SPEED: {
        int value;
        if (copy_from_user(&value, (const void*)arg, sizeof(int)))
            return -EFAULT;
        {
            SCOPED_LOCK(mutex, &lock);
            set_sample_rate(value);
            value = get_sample_rate();
        }
        if (copy_to_user((void*)arg, &value, sizeof(int)))
            return -EFAULT;
        return 0;
    }
    case SNDCTL_DSP_STEREO: {
        int value;
        if (copy_from_user(&value, (const void*)arg, sizeof(int)))
            return -EFAULT;
        value = 1;
        if (copy_to_user((void*)arg, &value, sizeof(int)))
            return -EFAULT;
        return 0;
    }
    case SNDCTL_DSP_CHANNELS: {
        int value;
        if (copy_from_user(&value, (const void*)arg, sizeof(int)))
            return -EFAULT;
        FALLTHROUGH;
    case SOUND_PCM_READ_CHANNELS:
        value = 2;
        if (copy_to_user((void*)arg, &value, sizeof(int)))
            return -EFAULT;
        return 0;
    }
    case SNDCTL_DSP_SETFMT: {
        int value;
        if (copy_from_user(&value, (const void*)arg, sizeof(int)))
            return -EFAULT;
        FALLTHROUGH;
    case SNDCTL_DSP_GETFMTS:
    case SOUND_PCM_READ_BITS:
        value = AFMT_S16_LE;
        if (copy_to_user((void*)arg, &value, sizeof(int)))
            return -EFAULT;
        return 0;
    }
    }
    return -EINVAL;
}

static short ac97_dsp_poll(struct file* file, short events) {
    (void)file;
    short revents = 0;
    if (events & POLLIN)
        revents |= POLLIN;
    if ((events & POLLOUT) && can_write())
        revents |= POLLOUT;
    return revents;
}

void ac97_init(void) {
    bool detected = false;
    pci_enumerate_devices(pci_device_callback, &detected);
    if (!detected)
        return;
    kprintf("ac97: detected device %x:%x:%x\n", device_addr.bus,
            device_addr.slot, device_addr.function);

    pci_set_interrupt_line_enabled(&device_addr, true);
    pci_set_bus_mastering_enabled(&device_addr, true);

    uint32_t control = in32(bus_base + BUS_GLOBAL_CONTROL);
    control |=
        GLOBAL_CONTROL_GPI_INTERRUPT_ENABLE | GLOBAL_CONTROL_AC97_COLD_RESET;
    out32(bus_base + BUS_GLOBAL_CONTROL, control);

    mixer_reset();
    dsp_reset();

    uint8_t irq_num = pci_get_interrupt_line(&device_addr);
    arch_interrupts_set_handler(IRQ(irq_num), irq_handler);

    static const struct file_ops mixer_fops = {
        .ioctl = ac97_mixer_ioctl,
    };
    static struct char_dev mixer = {
        .name = "mixer",
        .fops = &mixer_fops,
        .dev = makedev(SOUND_MAJOR, SND_DEV_CTL),
    };
    ASSERT_OK(char_dev_register(&mixer));

    static const struct file_ops dsp_fops = {
        .pwrite = ac97_dsp_pwrite,
        .ioctl = ac97_dsp_ioctl,
        .poll = ac97_dsp_poll,
    };
    static struct char_dev dsp = {
        .name = "dsp",
        .fops = &dsp_fops,
        .dev = makedev(SOUND_MAJOR, SND_DEV_DSP),
    };
    ASSERT_OK(char_dev_register(&dsp));
}
