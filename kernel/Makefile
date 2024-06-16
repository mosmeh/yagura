CFLAGS += -isystem..

TARGET := kernel

OBJS := \
	boot.o \
	cmdline.o \
	console/console.o \
	console/fb_console.o \
	console/psf.o \
	console/serial_console.o \
	console/system_console.o \
	console/tty.o \
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
	drivers/pseudo_device.o \
	drivers/rtc.o \
	drivers/serial.o \
	exec.o \
	fs/dentry.o \
	fs/fifo.o \
	fs/fs.o \
	fs/initrd.o \
	fs/procfs/pid.o \
	fs/procfs/procfs.o \
	fs/procfs/root.o \
	fs/tmpfs.o \
	fs/vfs.o \
	gdt.o \
	growable_buf.o \
	idt.o \
	interrupt.o \
	irq.o \
	kprintf.o \
	lock.o \
	main.o \
	memory/kmalloc.o \
	memory/page_allocator.o \
	memory/paging.o \
	memory/range_allocator.o \
	process.o \
	random.o \
	ring_buf.o \
	safe_string.o \
	scheduler.o \
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

$(TARGET): $(OBJS) linker.ld
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -Wl,-Tlinker.ld -Wl,--build-id=none -Wl,-z,noexecstack -o $@ $(OBJS)

.c.o:
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

.S.o:
	@echo "[AS] $<"
	@$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)
