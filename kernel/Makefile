CFLAGS += -isystem..

LINKER_SCRIPT := linker.ld
LDFLAGS += -Wl,-T$(LINKER_SCRIPT)

TARGET := kernel

OBJS := \
	acpi.o \
	boot.o \
	cmdline.o \
	console/console.o \
	console/font.o \
	console/key_map.o \
	console/screen/fb.o \
	console/screen/screen.o \
	console/screen/vga_text.o \
	console/serial_console.o \
	console/system_console.o \
	console/tty.o \
	console/virtual_console.o \
	console/vt.o \
	containers/vec.o \
	cpu.o \
	device/device.o \
	device/pseudo.o \
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
	drivers/rtc.o \
	drivers/serial.o \
	drivers/virtio/virtio_blk.o \
	drivers/virtio/virtio.o \
	exec.o \
	fs/filemap.o \
	fs/fs.o \
	fs/initrd.o \
	fs/path.o \
	fs/pipe.o \
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
	memory/vm_obj.o \
	memory/vm.o \
	random.o \
	safe_string.o \
	sched.o \
	smp.o \
	socket.o \
	syscall/dir.o \
	syscall/file_ctrl.o \
	syscall/file_io.o \
	syscall/fs.o \
	syscall/mmap.o \
	syscall/path.o \
	syscall/select.o \
	syscall/signal.o \
	syscall/socket.o \
	syscall/stat.o \
	syscall/syscall.o \
	syscall/system.o \
	syscall/task.o \
	syscall/time.o \
	system.o \
	task.o \
	time.o \
	../common/libgen.o \
	../common/stdio.o \
	../common/stdlib.o \
	../common/string.o \
	../common/tree.o \
	../common/ubsan.o

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
