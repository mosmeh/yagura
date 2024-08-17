CFLAGS += -isystem..

LINKER_SCRIPT := linker.ld
LDFLAGS := -Wl,-T$(LINKER_SCRIPT) -Wl,--build-id=none -Wl,-z,noexecstack

TARGET := kernel

OBJS := \
	acpi.o \
	boot.o \
	cmdline.o \
	console/console.o \
	console/screen/fb.o \
	console/screen/psf.o \
	console/screen/screen.o \
	console/screen/vga_text.o \
	console/serial_console.o \
	console/system_console.o \
	console/tty.o \
	console/virtual_console.o \
	console/vt.o \
	containers/vec.o \
	cpu.o \
	drivers/ac97.o \
	drivers/drivers.o \
	drivers/graphics/bochs.o \
	drivers/graphics/fb.o \
	drivers/graphics/multiboot.o \
	drivers/hid/keyboard.o \
	drivers/hid/mouse.o \
	drivers/hid/ps2.o \
	drivers/pci.o \
	drivers/pit.o \
	drivers/pseudo_devices.o \
	drivers/rtc.o \
	drivers/serial.o \
	drivers/virtio/virtio_blk.o \
	drivers/virtio/virtio.o \
	exec.o \
	fs/dentry.o \
	fs/fifo.o \
	fs/fs.o \
	fs/initrd.o \
	fs/path.o \
	fs/proc/pid.o \
	fs/proc/proc.o \
	fs/proc/root.o \
	fs/tmpfs.o \
	fs/vfs.o \
	gdt.o \
	interrupts/apic.o \
	interrupts/asm.o \
	interrupts/i8259.o \
	interrupts/idt.o \
	kmsg.o \
	ksyms.o \
	lock.o \
	main.o \
	memory/kmalloc.o \
	memory/memory.o \
	memory/page_table.o \
	memory/page.o \
	memory/slab.o \
	memory/vm.o \
	process.o \
	random.o \
	safe_string.o \
	scheduler.o \
	smp.o \
	syscall/clock.o \
	syscall/fs.o \
	syscall/mmap.o \
	syscall/poll.o \
	syscall/process.o \
	syscall/socket.o \
	syscall/syscall.o \
	system.o \
	time.o \
	unix_socket.o \
	../common/libgen.o \
	../common/math.o \
	../common/string.o \
	../common/strings.o \
 	../common/stdio.o \
 	../common/stdlib.o

DEPS := $(OBJS:.o=.d)

.PHONY: all clean

all: $(TARGET)

STAGES := \
	$(TARGET).stage0 \
	$(TARGET).stage1 \
	$(TARGET).stage2

# stage1 is built with an empty symbol table
$(TARGET).stage1: $(TARGET).stage0.ksyms.o $(OBJS) $(LINKER_SCRIPT)
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $<

# stage2 will have a correct list of symbols, but the addresses will be wrong
$(TARGET).stage2: $(TARGET).stage1.ksyms.o $(OBJS) $(LINKER_SCRIPT)
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $<

# stage3 will have correct addresses
$(TARGET): $(TARGET).stage2.ksyms.o $(OBJS) $(LINKER_SCRIPT)
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $<

$(TARGET).stage0.ksyms.o: ksyms.S
	@echo "[AS] $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

%.ksyms.o: ksyms.S %.ksyms
	@echo "[AS] $<"
	@$(CC) $(CFLAGS) -DKSYMS=$*.ksyms -c -o $@ $<

%.ksyms: %
	@echo "[KSYMS] $<"
	@nm -n $< > $@

.c.o:
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

.S.o:
	@echo "[AS] $<"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJS) $(KSYM_OBJS) $(DEPS) $(STAGES) $(STAGES:=.ksyms) $(STAGES:=.ksyms.o)

-include $(DEPS)
