CFLAGS := \
	-std=c11 \
	-m32 \
	-static \
	-nostdlib -ffreestanding \
	-U_FORTIFY_SOURCE \
	-I.. \
	-Wall -Wextra -pedantic \
	-O2 -g

TARGET := kernel

OBJS := \
	boot.o \
	console/console.o \
	console/psf.o \
	console/tty.o \
	fifo.o \
	fs/fs.o \
	fs/initrd.o \
	fs/shmfs.o \
	fs/tmpfs.o \
	fs/tree.o \
	fs/vfs.o \
	gdt.o \
	graphics/bochs.o \
	graphics/graphics.o \
	graphics/multiboot.o \
	hid/keyboard.o \
	hid/mouse.o \
	hid/ps2.o \
	idt.o \
	interrupt.o \
	irq.o \
	kmalloc.o \
	kprintf.o \
	lock.o \
	main.o \
	mem.o \
	pci.o \
	pit.o \
	process.o \
	pseudo_device.o \
	ring_buf.o \
	scheduler.o \
	serial.o \
	syscall/exec.o \
	syscall/file.o \
	syscall/mmap.o \
	syscall/process.o \
	syscall/socket.o \
	syscall/syscall.o \
	system.o \
	unix_socket.o \
 	../common/stdio.o \
	../common/stdlib.o \
 	../common/string.o

DEPS := $(OBJS:.o=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) linker.ld
	$(CC) $(CFLAGS) -Wl,-Tlinker.ld -Wl,--build-id=none -o $@ $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

.S.o:
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)
